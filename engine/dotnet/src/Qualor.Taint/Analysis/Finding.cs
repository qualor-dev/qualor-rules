using Microsoft.CodeAnalysis;

namespace Qualor.Taint;

/// The engine's limits for one run (spec §5 "Budgets"): over TimeLimit or MemoryLimitBytes the run stops and its result
/// is marked incomplete; MaxIterationsPerScc caps the fixed point of one strongly connected component of the call graph
/// (its analyses, per unit of the component, in one heap round), the rounds of one unit with its lambdas and local
/// functions, the heap rounds of the run (Task 8), and, times a method's block count, the fixed point of one method.
public sealed record TaintEngineOptions(TimeSpan TimeLimit, long MemoryLimitBytes, int MaxIterationsPerScc = 50)
{
    /// The directory the misuse rules' test-code globs are matched from (the scanned repository); null: the nearest
    /// directory above each file that holds `.git` (else the file's full path).
    public string? SourceRoot { get; init; }
}

/// What kind of edge a path step crosses (decision R-9, ruling R-E29). Value passing within the request is `high`
/// confidence: a local flow, a call resolved to the implementations the solution creates or registers, the view-model
/// edge (`View(model)` to the view's Model), a keyed request store entry with a constant key (ViewData, ViewBag,
/// HttpContext.Items). The others are `medium`: a field or property read from the heap, an entry written or read under a
/// key that is not a constant (a store's "any key" entry), a lookup whose key carries the request data (R-E9/R-E18), a
/// keyed store entry or view model a view reads only through an unresolved view name's fallback edges, and a call
/// resolved by the class-hierarchy fallback (no implementation known, or projects/types opened by scanning: R-7, Task 26)
/// to more than one implementation.
public enum StepKind
{
    /// A local flow, a resolved call, a source, a sink.
    Plain,

    /// A keyed request store entry under a constant key (high).
    KeyedEntry,

    /// The view model a view reads (the View(model) edge; high).
    ViewModel,

    /// A field or auto-property read from the heap (medium).
    HeapRead,

    /// A keyed store's "any key" entry: written or read with a key that is not a constant (medium).
    AnyKeyEntry,

    /// A lookup that passes its key's request data to the element found (R-E9/R-E18; medium).
    KeyLookup,

    /// A keyed entry or view model reached only through an unresolved view name's fallback edges (medium).
    ViewFallback,

    /// A call resolved by the class-hierarchy fallback to several implementations (medium).
    DispatchFallback,
}

/// A finding's confidence (R-9): High when its path crosses only high steps, Medium otherwise (shown as "possible").
public enum Confidence { High, Medium }

public static class StepKinds
{
    /// Whether a step of this kind makes a path medium confidence.
    public static bool IsMedium(this StepKind kind) => kind >= StepKind.HeapRead;

    /// The SARIF name of a step kind (`threadFlowLocations[].properties.kind`); null for a plain step.
    public static string? Name(this StepKind kind) => kind switch
    {
        StepKind.KeyedEntry => "keyed-entry",
        StepKind.ViewModel => "view-model",
        StepKind.HeapRead => "heap-read",
        StepKind.AnyKeyEntry => "any-key-entry",
        StepKind.KeyLookup => "key-lookup",
        StepKind.ViewFallback => "view-fallback",
        StepKind.DispatchFallback => "dispatch-fallback",
        _ => null,
    };
}

/// One step of a finding's path: "request data enters here", "assigned to 'sql'", "reaches the sink ...", with the kind
/// of edge it crosses (R-9).
public sealed record PathStep(Location Location, string Message)
{
    public PathStep(Location location, string message, StepKind kind)
        : this(location, message) => Kind = kind;

    public StepKind Kind { get; init; }

    /// Where to report the step: its mapped file and lines (see Finding.SinkSpan).
    public FileLinePositionSpan Span => Location.GetMappedLineSpan();
}

/// One result: a sink site of a rule (the location of the sink argument or of the assignment of a property sink), the
/// path from a source to it, and the other sources whose data reaches the same site.
public sealed record Finding(string RuleId, Location Sink, IReadOnlyList<PathStep> Path, IReadOnlyList<Location> OtherSources)
{
    /// What the sink is, when its model says more than the rule's generic text (a sink's `message:`, Task 29): the SARIF
    /// result's message then names it. Null: the rule's generic message.
    public string? Message { get; init; }

    /// Medium when the reported path crosses a medium step (R-9; decided on the whole path, also the steps a long path
    /// omits); a misuse finding is High.
    public Confidence Confidence { get; init; }

    /// Where to report the finding: the sink's mapped file and lines. In generated code with `#line` directives (a Razor
    /// view's `*_cshtml.g.cs` from the Razor source generator) that is the directive's file and line, the `.cshtml` the
    /// developer wrote, with the path as the generator wrote it (the build's absolute path, like the recorded sources);
    /// in a `#line hidden` region or a file without directives, the file's own path and line.
    public FileLinePositionSpan SinkSpan => Sink.GetMappedLineSpan();
}

/// What a run found. Complete is false when the run stopped early (a budget, cancellation, an iteration cap); its
/// findings are then partial and must not replace the OpenGrep rules (R-4).
public sealed record AnalysisResult(IReadOnlyList<Finding> Findings, bool Complete, string? IncompleteReason, AnalysisStats Stats);

/// Counters of a run: projects and method bodies (methods, accessors, lambdas, local functions, initializers)
/// analysed, strongly connected components (Task 8), distinct external call sites that got the `unmodelled-external`
/// default, the elapsed time and the peak working set seen. FailedMethods: bodies skipped because their analysis threw
/// (ruling R-E10: the run stays complete up to 1 % of the bodies), with the first FirstErrors (at most
/// MaxErrors, `<file>:<line>: <exception>: <message>`).
public sealed record AnalysisStats(int Projects, int Methods, int Sccs, int UnmodelledExternalCalls, TimeSpan Elapsed, long PeakMemoryBytes)
{
    public const int MaxErrors = 10;

    public int FailedMethods { get; init; }

    public IReadOnlyList<string> FirstErrors { get; init; } = Array.Empty<string>();

    /// The request entry points the heap is scoped to (spec §5 "Heap", decision R-6; EntryPoints): actions, Razor Pages
    /// handlers, Minimal API handlers, and bodies that read the request themselves but no entry point reaches.
    public int EntryPoints { get; init; }

    /// Views rendered by name (`View()`, `PartialView`, `Page()`, partials, view components) resolved to their
    /// generated classes; UnresolvedViews: those whose name could not be resolved, which reach every view of the
    /// caller's project instead.
    public int ViewEdges { get; init; }

    public int UnresolvedViews { get; init; }

    /// Views named by a path no compiled view has (compiled at run time, as plugin views often are): no edge, not a
    /// fallback.
    public int UncompiledViews { get; init; }

    /// Views no build compiled that the engine compiled (Task 30, R-11; distinct files over the solution), and those of
    /// them, or of the recorded views it could not compile at all, that have errors (counted, never fatal).
    public int CompiledByEngineViews { get; init; }

    public int EngineViewErrors { get; init; }

    /// Virtual and interface call sites with implementations in source (counted once, when the call graph is built, a
    /// property reference once for its getter and setter;
    /// Dispatch, decision R-7): resolved to the implementations the solution creates or registers
    /// (DispatchByRegistrations; DispatchNarrowed of them have fewer targets than the class hierarchy), to the
    /// implementations of projects or types opened by scanning, reflection or a missing registration
    /// (DispatchByScanning), or by the class hierarchy because none of the implementations is known
    /// (DispatchByHierarchy).
    public int DispatchByRegistrations { get; init; }

    public int DispatchNarrowed { get; init; }

    public int DispatchByScanning { get; init; }

    public int DispatchByHierarchy { get; init; }

    /// Projects all of whose types count as created (scanned, or with no registration in source), and types all of
    /// whose subtypes do (reflection).
    public int OpenProjects { get; init; }

    public int OpenTypes { get; init; }

    /// The findings by confidence (R-9).
    public int HighFindings { get; init; }

    public int MediumFindings { get; init; }
}
