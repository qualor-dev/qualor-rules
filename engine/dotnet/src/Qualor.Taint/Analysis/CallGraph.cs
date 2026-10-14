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

    public List<Unit> Units { get; } = new();

    public List<List<Unit>> Sccs { get; } = new();

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
                    if (!keepGoing()) return graph.Order(entries);
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
                        foreach (var callee in Callees(operation, dispatch)) unit.CalleeKeys.Add(dispatch.Key(callee));
                    }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        // The edges are an ordering aid: SummaryComputer records the calls a body really makes.
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
        return graph.Order(entries);
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
    internal static IEnumerable<IMethodSymbol> Callees(IOperation root, Dispatch dispatch)
    {
        foreach (var operation in root.DescendantsAndSelf())
        {
            switch (operation)
            {
                case IInvocationOperation invocation:
                    foreach (var t in dispatch.Targets(invocation.TargetMethod, invocation.IsVirtual, invocation.Instance?.Type)) yield return t;
                    break;
                case IObjectCreationOperation { Constructor: { } constructor }:
                    yield return constructor;
                    break;
                case IPropertyReferenceOperation property:
                {
                    var isVirtual = Dispatch.IsVirtualAccess(property.Property, property.Instance);
                    foreach (var accessor in new[] { property.Property.GetMethod, property.Property.SetMethod })
                        if (accessor != null)
                            foreach (var t in dispatch.Targets(accessor, isVirtual, property.Instance?.Type)) yield return t;
                    break;
                }
                case IMethodReferenceOperation reference:
                    foreach (var t in dispatch.Targets(reference.Method, reference.IsVirtual, reference.Instance?.Type)) yield return t;
                    break;
                // An object placed into a string built in place runs its ToString() (MethodAnalyzer.ImplicitToString).
                case IInterpolationOperation interpolation:
                    foreach (var t in ImplicitToString(interpolation.Expression, dispatch)) yield return t;
                    break;
                case IInterpolatedStringAppendOperation { AppendCall: IInvocationOperation { Arguments.Length: > 0 } call }:
                    foreach (var t in ImplicitToString(call.Arguments[0].Value, dispatch)) yield return t;
                    break;
                case IBinaryOperation { OperatorKind: BinaryOperatorKind.Add, Type.SpecialType: SpecialType.System_String } concatenation:
                    foreach (var t in ImplicitToString(concatenation.LeftOperand, dispatch)) yield return t;
                    foreach (var t in ImplicitToString(concatenation.RightOperand, dispatch)) yield return t;
                    break;
            }
        }
    }

    /// The ToString() overrides declared in source that turning this expression's value into text may run.
    private static IEnumerable<IMethodSymbol> ImplicitToString(IOperation expression, Dispatch dispatch)
    {
        while (expression is IConversionOperation { IsImplicit: true, Operand: { } inner } && !SymbolEqualityComparer.Default.Equals(inner.Type, expression.Type)) expression = inner;
        var type = expression.Type;
        if (type == null || type.SpecialType != SpecialType.None || type.TypeKind is TypeKind.Enum or TypeKind.Delegate or TypeKind.Dynamic or TypeKind.Array)
            return Array.Empty<IMethodSymbol>();
        IMethodSymbol? toString = null;
        for (var t = type; t != null && toString == null; t = t.BaseType)
            toString = t.GetMembers("ToString").OfType<IMethodSymbol>().FirstOrDefault(m => m.Parameters.Length == 0 && !m.IsStatic);
        if (toString == null || toString.ContainingType.SpecialType != SpecialType.None) return Array.Empty<IMethodSymbol>();
        return dispatch.Targets(toString, true, type);
    }

    /// Resolves the callee keys to units, adds the view edges (EntryPoints.Connect), computes the strongly connected
    /// components (Tarjan, iterative), then the entry points' reach.
    private CallGraph Order(EntryPoints? entries)
    {
        foreach (var unit in Units)
        {
            var seen = new HashSet<Unit>();
            foreach (var key in unit.CalleeKeys)
                if (_bodies.TryGetValue(key, out var body) && seen.Add(body.Unit)) unit.Callees.Add(body.Unit);
            unit.CalleeKeys.Clear();
        }
        entries?.Connect();
        Components();
        entries?.ComputeReach(this);
        return this;
    }

    private void Components()
    {
        var n = Units.Count;
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
                var callees = Units[v].Callees;
                var descended = false;
                while (i < callees.Count)
                {
                    var w = callees[i++].Id;
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
                        Units[w].Scc = Sccs.Count;
                        component.Add(Units[w]);
                    }
                    while (w != v);
                    Sccs.Add(component);
                }
                if (work.Count > 0)
                {
                    var parent = work.Peek().Unit;
                    low[parent] = Math.Min(low[parent], low[v]);
                }
            }
        }
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
