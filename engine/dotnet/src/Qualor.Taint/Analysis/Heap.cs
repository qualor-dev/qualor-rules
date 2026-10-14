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
/// Besides fields and properties, a location is an entry of a keyed request store (KeyedLocation, Task 22: ViewData and
/// ViewBag, HttpContext.Items, the view model), scoped the same way. A constant key is its own location; a key that is not
/// a constant writes the store's "any key" location, which a read of a constant key joins; a read whose key is not a
/// constant joins every location of the store.
///
/// The heap grows during the run; each symbol records the units that read it (with their Reach), and a write that
/// changes a symbol's value under some Reach (in the lattice, paths and source locations aside) makes the readers that
/// share an entry point with it dirty: SummaryComputer analyses them again, so the run ends at the joint fixed point of
/// the summaries and the heap.
internal sealed class Heap
{
    private readonly Dictionary<object, Writes> _values = new();
    private readonly Dictionary<object, HashSet<(Unit Unit, Reach Reach)>> _readers = new();
    private readonly HashSet<(object Key, Reach Writer)> _changed = new();
    private readonly Dictionary<ISymbol, bool> _members = new(SymbolEqualityComparer.Default);
    private readonly Dictionary<KeyedStore, HashSet<KeyedLocation>> _stores = new();
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

    /// The key of a location: a member's by its definition (Dispatch), a keyed store entry itself.
    public object Key(object location) => location is ISymbol member ? _dispatch.Key(SymbolKeys.Definition(member)) : location;

    /// The request data written to `member` so far under a Reach that shares an entry point with `reach` (the reading
    /// body's); `reader` is analysed again when that grows.
    public TaintValue Read(ISymbol member, Unit reader, Reach reach) => reach.IsEmpty ? TaintValue.Clean : ReadKey(Key(member), reader, reach);

    /// The request data of a keyed store entry for a reader (as Read): a constant key's entry joined with the store's
    /// "any key" entry; for a key that is not a constant, every entry of the store.
    public TaintValue Read(KeyedLocation location, Unit reader, Reach reach)
    {
        if (reach.IsEmpty) return TaintValue.Clean;
        if (location.Key != null) return ReadKey(location, reader, reach).Join(ReadKey(location.Any, reader, reach));
        var value = ReadKey(location.All, reader, reach);
        if (_stores.TryGetValue(location.Store, out var entries))
            foreach (var entry in entries) value = value.Join(ReadKey(entry, reader, reach));
        return value;
    }

    private TaintValue ReadKey(object key, Unit reader, Reach reach)
    {
        if (!_readers.TryGetValue(key, out var readers)) _readers[key] = readers = new HashSet<(Unit, Reach)>();
        readers.Add((reader, reach));
        if (!_values.TryGetValue(key, out var writes)) return TaintValue.Clean;
        var value = Read(writes.Writer, writes.Value, reach);
        if (writes.More != null)
            foreach (var (writer, written) in writes.More) value = value.Join(Read(writer, written, reach));
        return value;
    }

    private static TaintValue Read(Reach writer, TaintValue written, Reach reach)
    {
        var scope = writer.Intersect(reach);
        return scope.IsEmpty ? TaintValue.Clean : written.Narrowed(scope) with { FromHeap = true };
    }

    /// Joins the request data of `value` into `member` under `writer` (the writing body's WriteReach), narrowed to the
    /// value's own Scope. A writer no entry point reaches (fix round 1, I1: a constructor or initializer the call graph
    /// cannot connect) writes data it did not read from the heap under that data's Scope, the requests it came from.
    public void Write(object location, TaintValue value, Reach writer)
    {
        if (!value.Request) return;
        if (writer.IsEmpty)
        {
            if (value.Scope == null || value.FromHeap) return;
            writer = value.Scope;
        }
        else if (value.Scope != null)
        {
            var narrowed = writer.Intersect(value.Scope);
            // Heap data valid in none of the writer's requests is not written; data a helper read from the request (an
            // edge the call graph misses) is kept under the writer's own entry points.
            if (narrowed.IsEmpty && value.FromHeap) return;
            if (!narrowed.IsEmpty) writer = narrowed;
        }
        value = value.RequestPart.Narrowed(writer) with { FromHeap = false };
        var key = Key(location);
        if (location is KeyedLocation keyed && (!_stores.TryGetValue(keyed.Store, out var entries) || !entries.Contains(keyed)))
        {
            // A new entry of a store: the readers of every entry (a key that is not a constant) read it too.
            if (entries == null) _stores[keyed.Store] = entries = new HashSet<KeyedLocation>();
            entries.Add(keyed);
        }
        if (!_values.TryGetValue(key, out var writes))
        {
            _values[key] = new Writes(writer, value);
            Changed(key, writer);
            return;
        }
        TaintValue old;
        if (ReferenceEquals(writes.Writer, writer)) old = writes.Value;
        else if (writes.More == null || !writes.More.TryGetValue(writer, out old!))
        {
            (writes.More ??= new Dictionary<Reach, TaintValue>())[writer] = value;
            Changed(key, writer);
            return;
        }
        var joined = old.Join(value);
        if (ReferenceEquals(joined, old)) return;
        if (ReferenceEquals(writes.Writer, writer)) writes.Value = joined;
        else writes.More![writer] = joined;
        if (!joined.SameFlow(old)) Changed(key, writer);
    }

    /// A location's value changed under `writer`: its readers, and for a store entry the readers of every entry.
    private void Changed(object key, Reach writer)
    {
        _changed.Add((key, writer));
        if (key is KeyedLocation keyed) _changed.Add((keyed.All, writer));
    }

    /// The writes of one heap symbol: the first writer's inline (most symbols have one), the others in More.
    private sealed class Writes
    {
        public Writes(Reach writer, TaintValue value)
        {
            Writer = writer;
            Value = value;
        }

        public Reach Writer { get; }

        public TaintValue Value { get; set; }

        public Dictionary<Reach, TaintValue>? More { get; set; }
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
