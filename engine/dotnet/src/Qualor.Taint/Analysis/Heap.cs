using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Qualor.Taint;

/// The heap (spec §5 "Heap": fields and properties by symbol, field-based): a write of request data to a field or an
/// auto-property declared in source taints that symbol for the whole run, whatever the instance; a read of a tainted
/// symbol anywhere yields that request data. Only request data is stored (a parameter label is a body's own; a body's
/// summary records where its parameters reach the heap, and the call site writes what it substitutes for them).
///
/// The heap grows during the run; each symbol records the units that read it, and a symbol whose value changes (in the
/// lattice, paths and source locations aside) makes them dirty: SummaryComputer analyses them again, so the run ends at
/// the joint fixed point of the summaries and the heap.
internal sealed class Heap
{
    private readonly Dictionary<object, TaintValue> _values = new();
    private readonly Dictionary<object, HashSet<Unit>> _readers = new();
    private readonly HashSet<object> _changed = new();
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

    /// The request data written to `member` so far; `reader` is analysed again when it grows.
    public TaintValue Read(ISymbol member, Unit reader)
    {
        var key = Key(member);
        if (!_readers.TryGetValue(key, out var readers)) _readers[key] = readers = new HashSet<Unit>();
        readers.Add(reader);
        return _values.TryGetValue(key, out var value) ? value : TaintValue.Clean;
    }

    /// Joins the request data of `value` into `member`.
    public void Write(ISymbol member, TaintValue value)
    {
        if (!value.Request) return;
        value = value.RequestPart;
        var key = Key(member);
        if (!_values.TryGetValue(key, out var old))
        {
            _values[key] = value;
            _changed.Add(key);
            return;
        }
        var joined = old.Join(value);
        if (ReferenceEquals(joined, old)) return;
        _values[key] = joined;
        if (!joined.SameFlow(old)) _changed.Add(key);
    }

    /// The readers of the symbols that changed since the last call.
    public IEnumerable<Unit> TakeDirtyReaders()
    {
        if (_changed.Count == 0) return Array.Empty<Unit>();
        var dirty = new HashSet<Unit>();
        foreach (var key in _changed)
            if (_readers.TryGetValue(key, out var readers)) dirty.UnionWith(readers);
        _changed.Clear();
        return dirty;
    }
}
