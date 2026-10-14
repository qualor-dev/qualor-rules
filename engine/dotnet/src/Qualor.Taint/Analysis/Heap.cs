using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Qualor.Taint;

/// The heap (spec §5 "Heap" as amended, decision R-6): fields and properties by symbol, scoped to the request entry
/// point. A write of request data to a field or an auto-property declared in source records it under the entry points
/// that reach the writing body (EntryPoints.Of: a Reach); a read yields the request data written under a Reach that
/// shares an entry point with the reading body's, scoped to the shared entry points (TaintValue.Scope: a summary passes
/// it on only to callers those entry points reach). A body that no entry point reaches (a hosted service, startup code)
/// writes nothing a request can read and reads the heap clean. Only request data is stored (a parameter label is a
/// body's own; a body's summary records where its parameters reach the heap, and the call site writes what it
/// substitutes for them, under the callee's Reach).
///
/// The heap grows during the run; each symbol records the units that read it (with their Reach), and a write that
/// changes a symbol's value under some Reach (in the lattice, paths and source locations aside) makes the readers that
/// share an entry point with it dirty: SummaryComputer analyses them again, so the run ends at the joint fixed point of
/// the summaries and the heap.
internal sealed class Heap
{
    private readonly Dictionary<object, Dictionary<Reach, TaintValue>> _values = new();
    private readonly Dictionary<object, HashSet<(Unit Unit, Reach Reach)>> _readers = new();
    private readonly HashSet<(object Key, Reach Writer)> _changed = new();
    private readonly Dictionary<ISymbol, bool> _members = new(SymbolEqualityComparer.Default);
    private readonly Dispatch _dispatch;

    public Heap(Dispatch dispatch) => _dispatch = dispatch;

    /// The symbols tainted so far.
    public int Count => _values.Count;

    /// Whether a field or property is a heap location: a field declared in source (not a constant), or an
    /// auto-property declared in source (accessors without bodies, a positional record parameter's property).
    public bool IsMember(ISymbol member)
    {
        member = SymbolKeys.Definition(member);
        if (_members.TryGetValue(member, out var cached)) return cached;
        var result = member switch
        {
            IFieldSymbol field => !field.IsConst && SymbolKeys.InSource(field),
            IPropertySymbol property => IsAutoProperty(property),
            _ => false,
        };
        _members[member] = result;
        return result;
    }

    /// A property declared in source whose accessors have no bodies (it reads and writes a hidden field), or a
    /// positional record parameter's property.
    public static bool IsAutoProperty(IPropertySymbol property)
    {
        if (property.IsIndexer || property.IsAbstract || property.IsExtern || property.DeclaringSyntaxReferences.Length == 0) return false;
        if (property.ContainingType?.TypeKind == TypeKind.Interface) return false;
        return property.DeclaringSyntaxReferences[0].GetSyntax() switch
        {
            PropertyDeclarationSyntax p => p.ExpressionBody == null && p.AccessorList != null
                && p.AccessorList.Accessors.All(a => a.Body == null && a.ExpressionBody == null),
            ParameterSyntax => true,
            _ => false,
        };
    }

    public object Key(ISymbol member) => _dispatch.Key(SymbolKeys.Definition(member));

    /// The request data written to `member` so far under a Reach that shares an entry point with `reach` (the reading
    /// body's); `reader` is analysed again when that grows.
    public TaintValue Read(ISymbol member, Unit reader, Reach reach)
    {
        if (reach.IsEmpty) return TaintValue.Clean;
        var key = Key(member);
        if (!_readers.TryGetValue(key, out var readers)) _readers[key] = readers = new HashSet<(Unit, Reach)>();
        readers.Add((reader, reach));
        if (!_values.TryGetValue(key, out var writes)) return TaintValue.Clean;
        var value = TaintValue.Clean;
        foreach (var (writer, written) in writes)
        {
            var scope = writer.Intersect(reach);
            if (!scope.IsEmpty) value = value.Join(written with { Scope = scope, FromHeap = true });
        }
        return value;
    }

    /// Joins the request data of `value` into `member` under `writer` (the writing body's Reach), narrowed to the
    /// value's own Scope when it was read from the heap itself.
    public void Write(ISymbol member, TaintValue value, Reach writer)
    {
        if (!value.Request || writer.IsEmpty) return;
        if (value.Scope != null)
        {
            var narrowed = writer.Intersect(value.Scope);
            // Heap data valid in none of the writer's requests is not written; data a helper read from the request (an
            // edge the call graph misses) is kept under the writer's own entry points.
            if (narrowed.IsEmpty && value.FromHeap) return;
            if (!narrowed.IsEmpty) writer = narrowed;
        }
        value = value.RequestPart with { Scope = null, FromHeap = false };
        var key = Key(member);
        if (!_values.TryGetValue(key, out var writes)) _values[key] = writes = new Dictionary<Reach, TaintValue>();
        if (!writes.TryGetValue(writer, out var old))
        {
            writes[writer] = value;
            _changed.Add((key, writer));
            return;
        }
        var joined = old.Join(value);
        if (ReferenceEquals(joined, old)) return;
        writes[writer] = joined;
        if (!joined.SameFlow(old)) _changed.Add((key, writer));
    }

    /// The readers that share an entry point with a write that changed since the last call.
    public IEnumerable<Unit> TakeDirtyReaders()
    {
        if (_changed.Count == 0) return Array.Empty<Unit>();
        var dirty = new HashSet<Unit>();
        foreach (var (key, writer) in _changed)
            if (_readers.TryGetValue(key, out var readers))
                foreach (var (unit, reach) in readers)
                    if (reach.Intersects(writer)) dirty.Add(unit);
        _changed.Clear();
        return dirty;
    }
}
