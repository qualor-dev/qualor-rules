using System.Collections.Immutable;
using Microsoft.CodeAnalysis;

namespace Qualor.Taint;

/// The abstract value of an expression or a variable (spec §5): whether it carries request data (Request) and, if so,
/// the rules it has been cleaned for by a sanitizer (CleanFor: the value is dirty for every other rule). Path is one
/// witness from a source to here; Sources the source locations whose data it carries (at most MaxSources).
///
/// The lattice: a clean value (Request false) is the bottom; a request value is above it, and the smaller its CleanFor,
/// the higher. Join is the union of the request flags and the intersection of CleanFor (over the request values only:
/// a clean operand does not make a cleaned one dirty); Sources are united. Path does not take part in the order (it is
/// a witness, the shorter one is kept), so the fixed point ends when Request, CleanFor and Sources stop changing.
internal sealed record TaintValue(bool Request, ImmutableHashSet<string> CleanFor, ImmutableList<PathStep> Path)
{
    public const int MaxSources = 16;

    public static readonly TaintValue Clean = new(false, ImmutableHashSet<string>.Empty, ImmutableList<PathStep>.Empty);

    public ImmutableHashSet<Location> Sources { get; init; } = ImmutableHashSet<Location>.Empty;

    /// Request data that enters at `location` (a source).
    public static TaintValue Source(Location location, string message) =>
        new(true, ImmutableHashSet<string>.Empty, ImmutableList.Create(new PathStep(location, message)))
        {
            Sources = ImmutableHashSet.Create(location),
        };

    public bool TaintedFor(string rule) => Request && !CleanFor.Contains(rule);

    public TaintValue Join(TaintValue other)
    {
        if (!other.Request || ReferenceEquals(this, other)) return this;
        if (!Request) return other;
        var cleanFor = CleanFor.Count == 0 || other.CleanFor.Count == 0 ? ImmutableHashSet<string>.Empty : CleanFor.Intersect(other.CleanFor);
        var sources = Sources;
        foreach (var s in other.Sources)
        {
            if (sources.Count >= MaxSources) break;
            sources = sources.Add(s);
        }
        var path = other.Path.Count < Path.Count ? other.Path : Path;
        if (cleanFor.Count == CleanFor.Count && ReferenceEquals(sources, Sources) && ReferenceEquals(path, Path)) return this;
        return new TaintValue(true, cleanFor, path) { Sources = sources };
    }

    /// Equal in the lattice (Path aside).
    public bool SameTaint(TaintValue other) =>
        Request == other.Request && (!Request || (CleanFor.SetEquals(other.CleanFor) && Sources.SetEquals(other.Sources)));

    /// The value cleaned for these rules (a sanitizer's result).
    public TaintValue CleanedFor(IReadOnlyCollection<string> rules) =>
        !Request || rules.Count == 0 || rules.All(CleanFor.Contains) ? this : this with { CleanFor = CleanFor.Union(rules) };

    /// The value with one more path step (a request value only; a step at the last step's location is not repeated).
    public TaintValue Step(Location location, string message)
    {
        if (!Request || (Path.Count > 0 && Path[^1].Location.Equals(location))) return this;
        return this with { Path = Path.Add(new PathStep(location, message)) };
    }
}

/// The abstract state at a program point: a map from what holds a value (a local, a parameter, a field by symbol, a
/// flow capture of the control-flow graph by its CaptureId) to its TaintValue; an absent key is clean.
internal sealed class TaintState
{
    private readonly Dictionary<object, TaintValue> _map;

    public TaintState() => _map = new Dictionary<object, TaintValue>(SymbolOrCapture.Comparer);

    private TaintState(Dictionary<object, TaintValue> map) => _map = new Dictionary<object, TaintValue>(map, SymbolOrCapture.Comparer);

    public IEnumerable<KeyValuePair<object, TaintValue>> Entries => _map;

    public TaintValue Get(object key) => _map.TryGetValue(key, out var v) ? v : TaintValue.Clean;

    /// A strong update (an assignment).
    public void Set(object key, TaintValue value)
    {
        if (value.Request) _map[key] = value;
        else _map.Remove(key);
    }

    /// A weak update (a write into a collection or a builder the key holds): the old value joined with the new.
    public void Add(object key, TaintValue value)
    {
        if (!value.Request) return;
        _map[key] = Get(key).Join(value);
    }

    public TaintState Clone() => new(_map);

    /// Joins `other` into this state; true when this state changed (in the lattice).
    public bool JoinWith(TaintState other)
    {
        var changed = false;
        foreach (var (key, value) in other._map)
        {
            var old = Get(key);
            var joined = old.Join(value);
            if (joined.SameTaint(old)) continue;
            _map[key] = joined;
            changed = true;
        }
        return changed;
    }

}
