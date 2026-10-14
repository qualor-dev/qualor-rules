using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Qualor.Taint;

/// What a method does with request data and with its parameters, for its callers (spec §5 "Interprocedural"; the
/// brief's shape, a view of the engine's BodySummary): per parameter ordinal (−1 is `this`) its effect, whether the
/// method returns request data it read itself (a source, or a tainted heap symbol), and the fields and properties it
/// taints with such data itself.
public sealed record Summary(
    IReadOnlyDictionary<int, ParamEffect> Params,
    bool ReturnsRequest,
    IReadOnlyList<ISymbol> WritesHeapFromRequest);

/// One parameter's effect: whether it reaches the return value, the sinks it reaches inside the method (or its callees)
/// with the path from the parameter to there, the heap symbols it is written to (by the method or its callees), and the
/// rules it is cleaned for on its way to the return value.
public sealed record ParamEffect(
    bool ToReturn,
    IReadOnlyList<(string RuleId, Location Sink, IReadOnlyList<PathStep> Path)> ToSinks,
    IReadOnlyList<ISymbol> ToHeap,
    ImmutableHashSet<string> CleanFor);

/// A parameter of a body reaches a sink in the body itself (or in a lambda or local function nested in it): Slot the
/// parameter (−1 `this`), Site the sink argument's syntax (or the assignment of a property sink), Member the sink
/// member, Path the steps inside the body from its entry.
internal sealed record SinkEffect(int Slot, string RuleId, SyntaxNode Site, ISymbol Member, Trail Path);

/// A parameter of a body is passed to a parameter of a callee (CalleeSlot of Callee), cleaned on its way for CleanFor;
/// Path the steps inside the body from its entry to the callee's entry. The callee's own effects are not copied into
/// the caller: request data that reaches the parameter flows on along these edges (SummaryComputer.Seed).
internal sealed record CallEffect(int Slot, Body Callee, int CalleeSlot, ImmutableHashSet<string> CleanFor, Trail Path);

/// The engine's summary of one body, in the body's own parameter labels (TaintValue.Labels whose owner is the body;
/// a local function's summary may also hold labels of the body it is nested in, its captures, which a call site keeps).
///
/// Local effects, which a call site substitutes its arguments into:
/// - Return: the value returned (its request part is data the body reads itself: ReturnsRequest);
/// - ToThis: what is written into the receiver object (a constructor's: the object created);
/// - Refs: the value of each ref and out parameter at the exit.
///
/// Global effects, which request data reaching a parameter triggers (SummaryComputer.Seed), so a summary's size does not
/// grow with what its callees do (a chain of N calls costs N edges, not N² copied sinks):
/// - Sinks: the parameters that reach a sink in this body;
/// - Calls: the parameters passed on to a callee's parameters;
/// - Heap: the label part this body writes to each heap symbol (the request part goes to the Heap at once).
internal sealed class BodySummary
{
    public static readonly BodySummary Empty = new();

    public TaintValue Return { get; init; } = TaintValue.Clean;

    public TaintValue ToThis { get; init; } = TaintValue.Clean;

    public ImmutableDictionary<int, TaintValue> Refs { get; init; } = ImmutableDictionary<int, TaintValue>.Empty;

    public ImmutableDictionary<(int Slot, string Rule, SyntaxTree Tree, TextSpan Span), SinkEffect> Sinks { get; init; } =
        ImmutableDictionary<(int, string, SyntaxTree, TextSpan), SinkEffect>.Empty;

    public ImmutableDictionary<(int Slot, int Callee, int CalleeSlot), CallEffect> Calls { get; init; } =
        ImmutableDictionary<(int, int, int), CallEffect>.Empty;

    public ImmutableDictionary<object, (ISymbol Member, TaintValue Value)> Heap { get; init; } =
        ImmutableDictionary<object, (ISymbol, TaintValue)>.Empty;

    /// Heap symbols the body writes request data of its own to (for the public view).
    public ImmutableDictionary<object, ISymbol> RequestHeap { get; init; } = ImmutableDictionary<object, ISymbol>.Empty;

    /// No local effect: a call site gets nothing back.
    public bool NoLocalEffects => !Return.Any && !ToThis.Any && Refs.IsEmpty;

    public bool IsEmpty => NoLocalEffects && Sinks.IsEmpty && Calls.IsEmpty && Heap.IsEmpty && RequestHeap.IsEmpty;

    /// This summary joined with `other` (a body's summaries only grow, so the fixed point ends).
    public BodySummary Join(BodySummary other)
    {
        if (ReferenceEquals(this, other) || other.IsEmpty) return this;
        if (IsEmpty) return other;
        var refs = Refs;
        foreach (var (k, v) in other.Refs) refs = refs.SetItem(k, refs.TryGetValue(k, out var old) ? old.Join(v) : v);
        var sinks = Sinks;
        foreach (var (k, v) in other.Sinks) if (!sinks.ContainsKey(k)) sinks = sinks.Add(k, v);
        var calls = Calls;
        foreach (var (k, v) in other.Calls)
        {
            if (!calls.TryGetValue(k, out var old)) calls = calls.Add(k, v);
            else if (!old.CleanFor.IsSubsetOf(v.CleanFor)) calls = calls.SetItem(k, old with { CleanFor = old.CleanFor.Intersect(v.CleanFor) });
        }
        var heap = Heap;
        foreach (var (k, v) in other.Heap) heap = heap.SetItem(k, heap.TryGetValue(k, out var old) ? (old.Member, old.Value.Join(v.Value)) : v);
        var requestHeap = RequestHeap;
        foreach (var (k, v) in other.RequestHeap) if (!requestHeap.ContainsKey(k)) requestHeap = requestHeap.Add(k, v);
        return new BodySummary
        {
            Return = Return.Join(other.Return),
            ToThis = ToThis.Join(other.ToThis),
            Refs = refs,
            Sinks = sinks,
            Calls = calls,
            Heap = heap,
            RequestHeap = requestHeap,
        };
    }

    /// Equal in the local effects (paths and source locations aside): what decides whether callers are analysed again.
    public bool SameLocalEffects(BodySummary other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (!Return.SameFlow(other.Return) || !ToThis.SameFlow(other.ToThis) || Refs.Count != other.Refs.Count) return false;
        foreach (var (k, v) in Refs) if (!other.Refs.TryGetValue(k, out var o) || !v.SameFlow(o)) return false;
        return true;
    }

    /// Equal in the global effects: what decides whether the request data at the body's parameters flows on again.
    public bool SameGlobalEffects(BodySummary other)
    {
        if (ReferenceEquals(this, other)) return true;
        if (Sinks.Count != other.Sinks.Count || Calls.Count != other.Calls.Count || Heap.Count != other.Heap.Count) return false;
        foreach (var k in Sinks.Keys) if (!other.Sinks.ContainsKey(k)) return false;
        foreach (var (k, v) in Calls) if (!other.Calls.TryGetValue(k, out var o) || !v.CleanFor.SetEquals(o.CleanFor)) return false;
        foreach (var (k, v) in Heap) if (!other.Heap.TryGetValue(k, out var o) || !v.Value.SameFlow(o.Value)) return false;
        return true;
    }

    /// The value a call gets for a symbolic value of the callee `owner`: its request part (data the callee reads itself),
    /// and for each of the callee's labels the argument at that slot, through the callee's steps and cleaned as the
    /// callee cleans it. A label of another body (a local function's capture of its enclosing body) is kept when
    /// `keep` accepts its owner. Request data the callee read from the heap reaches the call only for the entry points
    /// that also reach the caller (`caller`; TaintValue.Scope).
    public static TaintValue Substitute(TaintValue symbolic, int owner, Func<int, TaintValue> argument, Location site, string name, Func<int, bool> keep,
        Reach caller)
    {
        if (!symbolic.Any) return TaintValue.Clean;
        var own = symbolic.RequestPart.Within(caller);
        var result = own.Request ? own.Step(site, $"returned by {name}") : TaintValue.Clean;
        foreach (var label in symbolic.Labels)
        {
            if (label.Owner == owner)
            {
                var a = argument(label.Slot);
                if (!a.Any) continue;
                result = result.Join(a.Step(site, $"passed to {name}").Extend(label.Path).CleanedFor(label.CleanFor));
            }
            else if (keep(label.Owner))
            {
                result = result.Join(TaintValue.Clean with { Labels = ImmutableArray.Create(label) });
            }
        }
        return result;
    }

    /// The request data a symbolic value of `owner` holds when `value` reaches parameter `slot` (its other labels
    /// clean): what a seed writes to the heap.
    public static TaintValue Through(TaintValue symbolic, int owner, int slot, TaintValue value)
    {
        var result = TaintValue.Clean;
        foreach (var label in symbolic.Labels)
            if (label.Owner == owner && label.Slot == slot) result = result.Join(value.Extend(label.Path).CleanedFor(label.CleanFor));
        return result;
    }
}

/// The summary of one body while it is analysed (and the bodies nested in it record effects on its labels).
internal sealed class SummaryBuilder
{
    public TaintValue Return = TaintValue.Clean;
    public TaintValue ToThis = TaintValue.Clean;
    public readonly Dictionary<int, TaintValue> Refs = new();
    public readonly Dictionary<(int Slot, string Rule, SyntaxTree Tree, TextSpan Span), SinkEffect> Sinks = new();
    public readonly Dictionary<(int Slot, int Callee, int CalleeSlot), CallEffect> Calls = new();
    public readonly Dictionary<object, (ISymbol Member, TaintValue Value)> Heap = new();
    public readonly Dictionary<object, ISymbol> RequestHeap = new();

    public void AddSink(int slot, string rule, SyntaxNode site, ISymbol member, Trail path) =>
        Sinks.TryAdd((slot, rule, site.SyntaxTree, site.Span), new SinkEffect(slot, rule, site, member, path));

    public void AddCall(int slot, Body callee, int calleeSlot, ImmutableHashSet<string> cleanFor, Trail path)
    {
        var key = (slot, callee.Id, calleeSlot);
        if (!Calls.TryGetValue(key, out var old)) Calls[key] = new CallEffect(slot, callee, calleeSlot, cleanFor, path);
        else if (!old.CleanFor.IsSubsetOf(cleanFor)) Calls[key] = old with { CleanFor = old.CleanFor.Intersect(cleanFor) };
    }

    public void AddHeap(object key, ISymbol member, TaintValue labels)
    {
        if (!labels.Any) return;
        Heap[key] = Heap.TryGetValue(key, out var old) ? (old.Member, old.Value.Join(labels)) : (member, labels);
    }

    public BodySummary Build() => new()
    {
        Return = Return,
        ToThis = ToThis,
        Refs = Refs.ToImmutableDictionary(),
        Sinks = Sinks.ToImmutableDictionary(),
        Calls = Calls.ToImmutableDictionary(),
        Heap = Heap.ToImmutableDictionary(),
        RequestHeap = RequestHeap.ToImmutableDictionary(),
    };
}
