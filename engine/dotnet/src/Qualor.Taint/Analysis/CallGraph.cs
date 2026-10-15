using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// One analysed body: a member's body (the root of a Unit) or a lambda or local function inside one. Its Id is the owner
/// of its parameter labels; Summary what its callers apply (only grows); Callers the units that applied it (analysed
/// again when it grows).
internal sealed class Body
{
    public Body(int id, Unit unit, IMethodSymbol? symbol, bool nested)
    {
        Id = id;
        Unit = unit;
        Symbol = symbol;
        Nested = nested;
    }

    public int Id { get; }

    public Unit Unit { get; }

    /// The body's symbol (null for an initializer or top-level statements). A lambda's or local function's symbol is
    /// the one of the latest binding of its unit.
    public IMethodSymbol? Symbol { get; set; }

    public bool Nested { get; }

    public bool IsLambda => Symbol?.MethodKind is MethodKind.AnonymousFunction;

    public BodySummary Summary { get; set; } = BodySummary.Empty;

    public HashSet<Unit> Callers { get; } = new();
}

/// The unit of the call graph and of SummaryComputer's worklist: one root of executable code (a method, constructor,
/// accessor, operator, expression-bodied property, field or property initializer, or a file's top-level statements)
/// with the lambdas and local functions inside it, which are analysed with it (they capture its variables). Callees are
/// the units its calls may run (Dispatch.Targets), from the operation tree.
internal sealed class Unit
{
    public Unit(int id, Compilation compilation, SyntaxNode root, IMethodSymbol? symbol)
    {
        Id = id;
        Compilation = compilation;
        Root = root;
        Symbol = symbol;
    }

    public int Id { get; }

    public Compilation Compilation { get; }

    public SyntaxNode Root { get; }

    public IMethodSymbol? Symbol { get; }

    public Body RootBody { get; set; } = null!;

    public List<object> CalleeKeys { get; } = new();

    /// The unit's virtual calls while the call graph is built: resolved once Dispatch knows what the solution creates
    /// (decision R-7).
    public List<CallSite>? PendingSites { get; set; }

    /// The callee keys only fallback dispatch gives (Dispatch.IsFallback: a class-hierarchy or scanning guess of more than
    /// one candidate) while the call graph is built; null when there are none.
    public HashSet<object>? FallbackKeys { get; set; }

    public List<Unit> Callees { get; } = new();

    /// The index of the unit's strongly connected component, callees' components first.
    public int Scc { get; set; }

    /// The bodies of the unit (the owners its labels may have).
    public HashSet<int> BodyIds { get; } = new();

    /// What the unit's bodies tell each other, kept across analyses (it only grows): the taint each lambda's parameters
    /// get at the calls it is given to, what each lambda returns, and what the lambdas and local functions write to the
    /// variables of the bodies they are nested in (`captured`).
    public Dictionary<object, TaintValue> LambdaSeeds { get; } = new();

    public Dictionary<object, TaintValue> LambdaReturns { get; } = new();

    public TaintState CapturedWrites { get; } = new();

    public bool HasCapturedWrites { get; set; }

    /// The unit's control-flow graph while it is cached (SummaryComputer keeps a bounded number).
    public ControlFlowGraph? Graph { get; set; }

    /// The unit's place in SummaryComputer's cache while its graph is cached.
    public LinkedListNode<Unit>? CacheNode { get; set; }
}

/// The call graph of the solution over units (spec §5): an edge from a unit to the unit of every body its calls,
/// object creations, property accesses and method groups may run, over every compilation (a project reference's
/// symbols are found by their declaring syntax, SymbolKeys); its strongly connected components by Tarjan's algorithm,
/// in bottom-up order (a component after every component it calls).
internal sealed class CallGraph
{
    private readonly Dictionary<object, Body> _bodies = new();
    private readonly List<Body> _all = new();
    private readonly Dispatch _dispatch;

    private CallGraph(Dispatch dispatch) => _dispatch = dispatch;

    private readonly HashSet<object> _methodGroups = new();
    private readonly HashSet<Unit> _called = new();

    /// Whether a method is used as a method group somewhere (a delegate: anything may call it).
    public bool IsMethodGroup(IMethodSymbol method) => _methodGroups.Contains(_dispatch.Key(method));

    /// Whether another unit's code may call the unit (an edge of the call graph from another unit).
    public bool IsCalled(Unit unit) => _called.Contains(unit);

    public List<Unit> Units { get; } = new();

    public List<List<Unit>> Sccs { get; } = new();

    /// The edges (caller, callee) only fallback dispatch gives: every call of the caller that may run the callee is a
    /// class-hierarchy or scanning guess of more than one candidate (Dispatch.IsFallback, R-9). They are edges of the
    /// call graph and of its components like any other; EntryPoints leaves them out of the precise reach (Task 32).
    public HashSet<(Unit From, Unit To)> FallbackCalls { get; } = new();

    public IReadOnlyList<Body> AllBodies => _all;

    public Body Body(int id) => _all[id];

    /// The body that runs for a member declared in source with a body (a method, accessor, constructor), or null.
    public Body? BodyOf(IMethodSymbol method) => _bodies.TryGetValue(_dispatch.Key(method), out var body) ? body : null;

    /// The unit of the body with this key (Dispatch.Key of a member), or null.
    public Unit? UnitOf(object key) => _bodies.TryGetValue(key, out var body) ? body.Unit : null;

    /// The body of a lambda or local function of `unit` (created when first met).
    public Body Nested(Unit unit, IMethodSymbol symbol)
    {
        var key = SymbolKeys.Of(symbol);
        if (_bodies.TryGetValue(key, out var body))
        {
            body.Symbol = symbol;
            return body;
        }
        body = new Body(_all.Count, unit, symbol, nested: true);
        _all.Add(body);
        _bodies[key] = body;
        unit.BodyIds.Add(body.Id);
        return body;
    }

    /// Indexes every root of every project (one binding of each), then orders the units. A root that fails to bind
    /// still gets a unit (its analysis fails and is counted, ruling R-E10). False from `keepGoing` stops early. `entries`
    /// scans each unit (EntryPoints.Scan), adds the view edges before the components are computed (EntryPoints.Connect)
    /// and computes the reach of each component after (EntryPoints.ComputeReach).
    public static CallGraph Build(LoadedSolution solution, Dispatch dispatch, Func<bool> keepGoing, CancellationToken ct, EntryPoints? entries = null)
    {
        var graph = new CallGraph(dispatch);
        foreach (var project in solution.Projects)
        {
            var compilation = project.Compilation;
            foreach (var tree in compilation.SyntaxTrees)
            {
                var model = compilation.GetSemanticModel(tree);
                foreach (var root in Roots(tree.GetRoot(ct)))
                {
                    if (!keepGoing()) return graph.Finish(entries);
                    ct.ThrowIfCancellationRequested();
                    IOperation? operation = null;
                    IMethodSymbol? symbol = null;
                    var bound = true;
                    try
                    {
                        operation = model.GetOperation(root, ct);
                        symbol = Symbol(root, model, ct);
                    }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        bound = false;
                    }
                    if (bound && !IsGraphRoot(operation)) continue;
                    var unit = graph.AddUnit(compilation, root, symbol);
                    if (operation == null) continue;
                    try
                    {
                        foreach (var site in CallSites(operation))
                        {
                            if (Dispatch.IsDispatched(site)) (unit.PendingSites ??= new List<CallSite>()).Add(site);
                            else unit.CalleeKeys.Add(dispatch.Key(SymbolKeys.Definition(site.Method)));
                        }
                        foreach (var reference in operation.DescendantsAndSelf().OfType<IMethodReferenceOperation>())
                            foreach (var t in dispatch.Targets(reference.Method, reference.IsVirtual, reference.Instance?.Type)) graph._methodGroups.Add(dispatch.Key(t));
                    }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        // The edges are an ordering aid: SummaryComputer records the calls a body really makes.
                    }
                    try
                    {
                        dispatch.Collect(operation, compilation);
                    }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        // What the body creates stays unknown; the rest of the solution still narrows dispatch.
                    }
                    try
                    {
                        entries?.Scan(unit, operation, dispatch);
                    }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        // A unit whose scan fails is no entry point and renders no view (its reach comes from its callers).
                    }
                }
            }
        }
        return graph.Finish(entries);
    }

    /// Seals what the solution creates (Dispatch.Seal), resolves the virtual calls kept pending (counting each site in
    /// the dispatch stats), then orders the units.
    private CallGraph Finish(EntryPoints? entries)
    {
        _dispatch.Seal();
        foreach (var unit in Units)
        {
            if (unit.PendingSites is not { } sites) continue;
            unit.PendingSites = null;
            // The keys that are no guess: the calls that need no dispatch (in CalleeKeys already) and the dispatched
            // targets of no fallback.
            var direct = unit.CalleeKeys.Count;
            HashSet<object>? sure = null;
            try
            {
                foreach (var site in sites)
                {
                    _dispatch.Count(site);
                    foreach (var target in _dispatch.Targets(site))
                    {
                        var key = _dispatch.Key(target);
                        unit.CalleeKeys.Add(key);
                        if (_dispatch.IsFallback(site.Method, site.IsVirtual, site.Receiver, target)) (unit.FallbackKeys ??= new HashSet<object>()).Add(key);
                        else (sure ??= new HashSet<object>()).Add(key);
                    }
                }
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // As above: an ordering aid.
            }
            if (unit.FallbackKeys is { } fallback)
            {
                if (sure != null) fallback.ExceptWith(sure);
                fallback.ExceptWith(unit.CalleeKeys.Take(direct));
                if (fallback.Count == 0) unit.FallbackKeys = null;
            }
        }
        return Order(entries);
    }

    private Unit AddUnit(Compilation compilation, SyntaxNode root, IMethodSymbol? symbol)
    {
        var unit = new Unit(Units.Count, compilation, root, symbol);
        Units.Add(unit);
        var body = new Body(_all.Count, unit, symbol, nested: false);
        _all.Add(body);
        unit.RootBody = body;
        unit.BodyIds.Add(body.Id);
        var key = symbol != null ? _dispatch.Key(symbol) : SymbolKeys.Of(root);
        _bodies.TryAdd(key, body);
        return unit;
    }

    /// The methods an operation tree may call (invocations, object creations, property accessors, method groups).
    internal static IEnumerable<IMethodSymbol> Callees(IOperation root, Dispatch dispatch) => CallSites(root).SelectMany(dispatch.Targets);

    /// The calls an operation tree makes (invocations, object creations, property accessors, method groups, implicit
    /// ToString()), before dispatch.
    internal static IEnumerable<CallSite> CallSites(IOperation root)
    {
        foreach (var operation in root.DescendantsAndSelf())
        {
            switch (operation)
            {
                case IInvocationOperation invocation:
                    yield return new CallSite(invocation.TargetMethod, invocation.IsVirtual, invocation.Instance?.Type);
                    break;
                case IObjectCreationOperation { Constructor: { } constructor }:
                    yield return new CallSite(constructor, false, null);
                    break;
                case IPropertyReferenceOperation property:
                {
                    var isVirtual = Dispatch.IsVirtualAccess(property.Property, property.Instance);
                    var getter = property.Property.GetMethod;
                    if (getter != null) yield return new CallSite(getter, isVirtual, property.Instance?.Type);
                    if (property.Property.SetMethod is { } setter) yield return new CallSite(setter, isVirtual, property.Instance?.Type, getter == null);
                    break;
                }
                case IMethodReferenceOperation reference:
                    yield return new CallSite(reference.Method, reference.IsVirtual, reference.Instance?.Type);
                    break;
                // An object placed into a string built in place runs its ToString() (MethodAnalyzer.ImplicitToString).
                case IInterpolationOperation interpolation:
                    if (ImplicitToString(interpolation.Expression) is { } a) yield return a;
                    break;
                case IInterpolatedStringAppendOperation { AppendCall: IInvocationOperation { Arguments.Length: > 0 } call }:
                    if (ImplicitToString(call.Arguments[0].Value) is { } b) yield return b;
                    break;
                case IBinaryOperation { OperatorKind: BinaryOperatorKind.Add, Type.SpecialType: SpecialType.System_String } concatenation:
                    if (ImplicitToString(concatenation.LeftOperand) is { } left) yield return left;
                    if (ImplicitToString(concatenation.RightOperand) is { } right) yield return right;
                    break;
            }
        }
    }

    /// The ToString() call (of a method declared in source) that turning this expression's value into text makes, or null.
    private static CallSite? ImplicitToString(IOperation expression)
    {
        while (expression is IConversionOperation { IsImplicit: true, Operand: { } inner } && !SymbolEqualityComparer.Default.Equals(inner.Type, expression.Type)) expression = inner;
        var type = expression.Type;
        if (type == null || type.SpecialType != SpecialType.None || type.TypeKind is TypeKind.Enum or TypeKind.Delegate or TypeKind.Dynamic or TypeKind.Array)
            return null;
        IMethodSymbol? toString = null;
        for (var t = type; t != null && toString == null; t = t.BaseType)
            toString = t.GetMembers("ToString").OfType<IMethodSymbol>().FirstOrDefault(m => m.Parameters.Length == 0 && !m.IsStatic);
        if (toString == null || toString.ContainingType.SpecialType != SpecialType.None) return null;
        return new CallSite(toString, true, type);
    }

    /// Resolves the callee keys to units, adds the view edges (EntryPoints.Connect), computes the strongly connected
    /// components (Tarjan, iterative), then the entry points' reach.
    private CallGraph Order(EntryPoints? entries)
    {
        foreach (var unit in Units)
        {
            var seen = new HashSet<Unit>();
            var fallback = unit.FallbackKeys;
            HashSet<Unit>? guessed = null;
            HashSet<Unit>? sure = null;
            foreach (var key in unit.CalleeKeys)
            {
                if (!_bodies.TryGetValue(key, out var body)) continue;
                if (seen.Add(body.Unit)) unit.Callees.Add(body.Unit);
                // A callee only fallback keys give is a fallback edge (another key of the same unit is a sure call).
                if (fallback == null) continue;
                if (fallback.Contains(key)) (guessed ??= new HashSet<Unit>()).Add(body.Unit);
                else (sure ??= new HashSet<Unit>()).Add(body.Unit);
            }
            if (guessed != null)
                foreach (var callee in guessed)
                    if (callee != unit && (sure == null || !sure.Contains(callee))) FallbackCalls.Add((unit, callee));
            unit.CalleeKeys.Clear();
            unit.FallbackKeys = null;
            foreach (var callee in unit.Callees)
                if (callee != unit) _called.Add(callee);
        }
        entries?.Connect();
        Components();
        entries?.ComputeReach(this);
        return this;
    }

    private void Components()
    {
        var (of, components) = StronglyConnected(Units, null);
        foreach (var unit in Units) unit.Scc = of[unit.Id];
        Sccs.AddRange(components);
    }

    /// The strongly connected components of `units` (a unit's Id is its index) over the edges `keep` accepts (every
    /// edge when null), by Tarjan's algorithm (iterative), in bottom-up order (a component after every component it
    /// calls); `Of[unit.Id]` is the index of the unit's component.
    internal static (int[] Of, List<List<Unit>> Components) StronglyConnected(List<Unit> units, Func<Unit, Unit, bool>? keep)
    {
        var sccs = new List<List<Unit>>();
        var n = units.Count;
        var of = new int[n];
        var index = new int[n];
        var low = new int[n];
        var onStack = new bool[n];
        Array.Fill(index, -1);
        var stack = new Stack<int>();
        var work = new Stack<(int Unit, int Next)>();
        var counter = 0;
        for (var s = 0; s < n; s++)
        {
            if (index[s] != -1) continue;
            work.Push((s, 0));
            while (work.Count > 0)
            {
                var (v, i) = work.Pop();
                if (i == 0)
                {
                    index[v] = low[v] = counter++;
                    stack.Push(v);
                    onStack[v] = true;
                }
                var callees = units[v].Callees;
                var descended = false;
                while (i < callees.Count)
                {
                    var callee = callees[i++];
                    if (keep != null && !keep(units[v], callee)) continue;
                    var w = callee.Id;
                    if (index[w] == -1)
                    {
                        work.Push((v, i));
                        work.Push((w, 0));
                        descended = true;
                        break;
                    }
                    if (onStack[w]) low[v] = Math.Min(low[v], index[w]);
                }
                if (descended) continue;
                if (low[v] == index[v])
                {
                    var component = new List<Unit>();
                    int w;
                    do
                    {
                        w = stack.Pop();
                        onStack[w] = false;
                        of[w] = sccs.Count;
                        component.Add(units[w]);
                    }
                    while (w != v);
                    sccs.Add(component);
                }
                if (work.Count > 0)
                {
                    var parent = work.Peek().Unit;
                    low[parent] = Math.Min(low[parent], low[v]);
                }
            }
        }
        return (of, sccs);
    }

    public static bool IsGraphRoot(IOperation? operation) => operation is IMethodBodyOperation or IConstructorBodyOperation
        or IBlockOperation { Parent: null } or IFieldInitializerOperation or IPropertyInitializerOperation;

    public static ControlFlowGraph? Graph(IOperation? operation, CancellationToken ct) => operation switch
    {
        IMethodBodyOperation body => ControlFlowGraph.Create(body, ct),
        IConstructorBodyOperation body => ControlFlowGraph.Create(body, ct),
        IBlockOperation { Parent: null } block => ControlFlowGraph.Create(block, ct),
        IFieldInitializerOperation field => ControlFlowGraph.Create(field, ct),
        IPropertyInitializerOperation property => ControlFlowGraph.Create(property, ct),
        _ => null,
    };

    public static IMethodSymbol? Symbol(SyntaxNode root, SemanticModel model, CancellationToken ct) => root switch
    {
        BaseMethodDeclarationSyntax or AccessorDeclarationSyntax => model.GetDeclaredSymbol(root, ct) as IMethodSymbol,
        ArrowExpressionClauseSyntax { Parent: BasePropertyDeclarationSyntax property } =>
            (model.GetDeclaredSymbol(property, ct) as IPropertySymbol)?.GetMethod,
        _ => null,
    };

    /// The roots of executable code in a tree; lambdas and local functions are reached through their enclosing
    /// graph. Method bodies and expressions are not descended into (they declare no members).
    public static IEnumerable<SyntaxNode> Roots(SyntaxNode root)
    {
        foreach (var node in root.DescendantNodesAndSelf(n => n is not (BlockSyntax or ArrowExpressionClauseSyntax
                     or EqualsValueClauseSyntax or GlobalStatementSyntax or ExpressionSyntax or ParameterListSyntax
                     or AttributeListSyntax)))
        {
            switch (node)
            {
                case CompilationUnitSyntax unit when unit.Members.Any(m => m is GlobalStatementSyntax):
                    yield return unit;
                    break;
                case BaseMethodDeclarationSyntax method when method.Body != null || method.ExpressionBody != null:
                    yield return method;
                    break;
                case AccessorDeclarationSyntax accessor when accessor.Body != null || accessor.ExpressionBody != null:
                    yield return accessor;
                    break;
                case ArrowExpressionClauseSyntax { Parent: PropertyDeclarationSyntax or IndexerDeclarationSyntax } arrow:
                    yield return arrow;
                    break;
                case EqualsValueClauseSyntax { Parent: VariableDeclaratorSyntax { Parent.Parent: FieldDeclarationSyntax } } field:
                    yield return field;
                    break;
                case EqualsValueClauseSyntax { Parent: PropertyDeclarationSyntax } property:
                    yield return property;
                    break;
            }
        }
    }
}
