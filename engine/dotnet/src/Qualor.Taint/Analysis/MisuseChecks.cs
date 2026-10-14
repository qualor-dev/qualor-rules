using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// The checks of the misuse rules (`kind: misuse`, models/README.md `misuse:`), run over every syntax tree of every
/// project that is not test code for the rule (`test-code:`): a dangerous call, setting or callback is a finding
/// wherever it is, whatever the data. The trees are walked by syntax; a node is bound only when a name the models
/// use appears in it (a prefilter: the decision is always the semantic model's).
///
/// - `calls`: an invocation (or a read of a property) whose member matches, by the receiver's type.
/// - `enum-values`: a constant of the enum (the value, not its text) other than a safe member, written to a field or
///   property of the enum type (or Nullable of it): an assignment, an object initializer, an attribute's named
///   argument, a field or property initializer.
/// - `values`: the value given to a member (the assigned value of a property, also `+=`; a constructor's or method's
///   argument; `new D(x)` of a delegate type D is D's constructor with x at 0) may be, directly or through `?:`, `??`
///   and a local assigned in the body (and written no other way), a creation of one of `created` (any constructor,
///   with or without an initializer) or a callback (lambda, anonymous method) that accepts all; `with` / `without`:
///   the object written to has (never has) the property set to one of the enum members anywhere in the body (the
///   access paths of BodyFacts).
/// - `accepts-all-methods`: a method or local function with a parameter of the type that returns bool and accepts all.
///
/// A callback accepts all when every return of its own body (nested lambdas and local functions apart) returns an
/// always-true value (a constant true; `a || b` with one side, `a && b` and `c ? a : b` with both sides always true)
/// and the body throws nowhere.
internal sealed class MisuseChecks
{
    private readonly IReadOnlyList<RuleModel> _rules;
    private readonly HashSet<string> _invokedNames = new(StringComparer.Ordinal);
    private readonly List<string> _invokedPrefixes = new();
    private readonly HashSet<string> _readNames = new(StringComparer.Ordinal);
    private readonly HashSet<string> _assignedNames = new(StringComparer.Ordinal);
    private readonly HashSet<string> _createdNames = new(StringComparer.Ordinal);
    private readonly List<string> _enumNames = new();
    private readonly bool _ctorCalls;
    private readonly HashSet<string> _parameterTypeNames = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _relative = new(StringComparer.Ordinal);
    private readonly List<string> _errors = new();

    public MisuseChecks(IEnumerable<RuleModel> rules)
    {
        _rules = rules.Where(r => r.Kind == RuleKind.Misuse && r.Misuse != null).ToList();
        foreach (var m in _rules.Select(r => r.Misuse!))
        {
            foreach (var p in m.Calls.Concat(m.Values.Select(v => v.Member)))
            {
                switch (p.Kind)
                {
                    case MemberKind.Constructor: _createdNames.Add(SimpleName(p.TypeName)); break;
                    case MemberKind.PropertyGet: _readNames.Add(p.MemberName); break;
                    case MemberKind.PropertySet: _assignedNames.Add(p.MemberName); break;
                    default:
                        if (p.Prefix) _invokedPrefixes.Add(p.MemberName);
                        else _invokedNames.Add(p.MemberName);
                        break;
                }
            }
            _ctorCalls |= m.Calls.Any(p => p.Kind == MemberKind.Constructor);
            foreach (var e in m.EnumValues) _enumNames.Add(SimpleName(e.Type));
            if (m.AcceptsAllMethods != null) _parameterTypeNames.Add(SimpleName(m.AcceptsAllMethods));
        }
    }

    /// Trees whose check threw (skipped, like a failed body under ruling R-E10), and the trees checked.
    public int Failed { get; private set; }

    public int Checked { get; private set; }

    public IReadOnlyList<string> Errors => _errors;

    /// Checks every tree of every project; stops (returns) when the budget says so. A tree whose check throws is
    /// skipped and counted.
    public void Run(LoadedSolution solution, Budget budget, AnalysisContext ctx, CancellationToken ct)
    {
        if (_rules.Count == 0) return;
        foreach (var project in solution.Projects)
        {
            var aliases = AliasNames(project.Compilation, ct);
            foreach (var tree in project.Compilation.SyntaxTrees)
            {
                if (!budget.Check()) return;
                var relative = Relative(tree.FilePath, ctx.Options.SourceRoot);
                var rules = _rules.Where(r => !TestCode.Matches(relative, r.Misuse!.TestCode)).ToList();
                if (rules.Count == 0) continue;
                try
                {
                    new TreeCheck(this, rules, project.Compilation, tree, aliases, ctx, ct).Run();
                    Checked++;
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    Failed++;
                    if (_errors.Count < AnalysisStats.MaxErrors) _errors.Add($"{tree.FilePath}: misuse checks: {e.GetType().Name}: {e.Message}");
                }
            }
        }
    }

    private string Relative(string path, string? root)
    {
        if (!_relative.TryGetValue(path, out var relative)) _relative[path] = relative = TestCode.Relative(path, root);
        return relative;
    }

    /// The names of the compilation's using aliases (`using X = ...;`, global ones too): a type may be written as one.
    private static HashSet<string> AliasNames(Compilation compilation, CancellationToken ct)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var tree in compilation.SyntaxTrees)
        {
            foreach (var u in tree.GetRoot(ct).DescendantNodes(n => n is CompilationUnitSyntax or BaseNamespaceDeclarationSyntax).OfType<UsingDirectiveSyntax>())
                if (u.Alias != null) names.Add(u.Alias.Name.Identifier.ValueText);
        }
        return names;
    }

    /// `Newtonsoft.Json.TypeNameHandling` → `TypeNameHandling`; `A.B+C`1` → `C`.
    private static string SimpleName(string typeName)
    {
        var name = typeName[(typeName.LastIndexOfAny(new[] { '.', '+' }) + 1)..];
        var tick = name.IndexOf('`');
        return tick < 0 ? name : name[..tick];
    }

    private bool Invoked(string name) => _invokedNames.Contains(name) || _invokedPrefixes.Any(p => name.StartsWith(p, StringComparison.Ordinal));

    private bool MentionsEnum(SyntaxNode node) =>
        _enumNames.Count > 0 && node.DescendantTokens().Any(t => t.IsKind(SyntaxKind.IdentifierToken) && _enumNames.Any(e => t.ValueText.Contains(e, StringComparison.Ordinal)));

    /// The rightmost identifier of a (possibly qualified or generic) name or type.
    private static string? RightmostName(SyntaxNode? node) => node switch
    {
        SimpleNameSyntax s => s.Identifier.ValueText,
        QualifiedNameSyntax q => q.Right.Identifier.ValueText,
        AliasQualifiedNameSyntax a => a.Name.Identifier.ValueText,
        MemberAccessExpressionSyntax m => m.Name.Identifier.ValueText,
        MemberBindingExpressionSyntax b => b.Name.Identifier.ValueText,
        NullableTypeSyntax n => RightmostName(n.ElementType),
        _ => null,
    };

    /// The checks of one tree for the rules that apply to it.
    private sealed class TreeCheck
    {
        private readonly MisuseChecks _owner;
        private readonly IReadOnlyList<RuleModel> _rules;
        private readonly Compilation _compilation;
        private readonly SyntaxTree _tree;
        private readonly HashSet<string> _aliases;
        private readonly AnalysisContext _ctx;
        private readonly CancellationToken _ct;
        private readonly Dictionary<SyntaxNode, BodyFacts> _facts = new();
        private SemanticModel? _model;

        public TreeCheck(MisuseChecks owner, IReadOnlyList<RuleModel> rules, Compilation compilation, SyntaxTree tree, HashSet<string> aliases, AnalysisContext ctx, CancellationToken ct)
        {
            _owner = owner;
            _rules = rules;
            _compilation = compilation;
            _tree = tree;
            _aliases = aliases;
            _ctx = ctx;
            _ct = ct;
        }

        private SemanticModel Model => _model ??= _compilation.GetSemanticModel(_tree);

        public void Run()
        {
            foreach (var node in _tree.GetRoot(_ct).DescendantNodes())
            {
                _ct.ThrowIfCancellationRequested();
                switch (node)
                {
                    case InvocationExpressionSyntax invocation when RightmostName(invocation.Expression) is { } name && _owner.Invoked(name):
                        if (Bound(invocation) is IInvocationOperation call) Invocation(call, invocation);
                        break;
                    case BaseObjectCreationExpressionSyntax creation when Created(creation):
                        Creation(Bound(creation), creation);
                        break;
                    case AssignmentExpressionSyntax assignment:
                        if (RightmostName(assignment.Left) is { } assigned && _owner._assignedNames.Contains(assigned)
                            && Model.GetOperation(assignment, _ct) is IAssignmentOperation op)
                            Assignment(op);
                        if (_owner.MentionsEnum(assignment) || MentionsAlias(assignment)) EnumValue(assignment.Left, assignment.Right, assignment);
                        break;
                    case MemberAccessExpressionSyntax access when _owner._readNames.Contains(access.Name.Identifier.ValueText):
                        Read(access, access.Name);
                        break;
                    case IdentifierNameSyntax identifier when _owner._readNames.Contains(identifier.Identifier.ValueText)
                        && !(identifier.Parent is MemberAccessExpressionSyntax m && m.Name == identifier)
                        && identifier.Parent is not (MemberBindingExpressionSyntax or NameEqualsSyntax or QualifiedNameSyntax):
                        Read(identifier, identifier);
                        break;
                    case AttributeArgumentSyntax { NameEquals: { } nameEquals } argument when _owner.MentionsEnum(argument) || MentionsAlias(argument):
                        EnumValue(nameEquals.Name, argument.Expression, argument);
                        break;
                    case VariableDeclaratorSyntax { Initializer: { } init } declarator when declarator.Parent?.Parent is BaseFieldDeclarationSyntax && (_owner.MentionsEnum(declarator) || MentionsAlias(declarator)):
                        EnumValue(Model.GetDeclaredSymbol(declarator, _ct), init.Value, init.Value);
                        break;
                    case PropertyDeclarationSyntax { Initializer: { } init } property when _owner.MentionsEnum(property) || MentionsAlias(property):
                        EnumValue(Model.GetDeclaredSymbol(property, _ct), init.Value, init.Value);
                        break;
                    case MethodDeclarationSyntax method when TakesParameterType(method.ParameterList):
                        Method(method, method.Identifier);
                        break;
                    case LocalFunctionStatementSyntax local when TakesParameterType(local.ParameterList):
                        Method(local, local.Identifier);
                        break;
                }
            }
        }

        /// The node's operation without the implicit conversions the semantic model may wrap it in.
        private IOperation? Bound(SyntaxNode node)
        {
            var op = Model.GetOperation(node, _ct);
            while (op is IConversionOperation { IsImplicit: true } c && c.Operand.Syntax == node) op = c.Operand;
            return op;
        }

        private bool MentionsAlias(SyntaxNode node) =>
            _aliases.Count > 0 && node.DescendantTokens().Any(t => t.IsKind(SyntaxKind.IdentifierToken) && _aliases.Contains(t.ValueText));

        private bool Created(BaseObjectCreationExpressionSyntax creation) => creation switch
        {
            ObjectCreationExpressionSyntax explicitType => RightmostName(explicitType.Type) is { } name && (_owner._createdNames.Contains(name) || _aliases.Contains(name)),
            // `new(...)` names no type: bound when it has arguments (a value check's) or a constructor is a call to report.
            _ => _owner._createdNames.Count > 0 && (creation.ArgumentList is { Arguments.Count: > 0 } || _owner._ctorCalls),
        };

        private bool TakesParameterType(ParameterListSyntax parameters) =>
            _owner._parameterTypeNames.Count > 0
            && parameters.Parameters.Any(p => RightmostName(p.Type) is { } name && (_owner._parameterTypeNames.Contains(name) || _aliases.Contains(name)));

        // calls: and values: of methods.
        private void Invocation(IInvocationOperation call, InvocationExpressionSyntax syntax)
        {
            var at = (RightmostNameNode(syntax.Expression) ?? syntax).GetLocation();
            foreach (var rule in _rules)
            {
                var m = rule.Misuse!;
                foreach (var p in m.Calls)
                    if (p.Kind == MemberKind.Method && SymbolMatch.Matches(p, call.TargetMethod))
                        Report(rule, at, $"calls {_ctx.Name(call.TargetMethod)}");
                foreach (var v in m.Values)
                    if (v.Member.Kind == MemberKind.Method && SymbolMatch.Matches(v.Member, call.TargetMethod))
                        Arguments(rule, v, call, call.TargetMethod);
            }
        }

        private static SyntaxNode? RightmostNameNode(ExpressionSyntax expression) => expression switch
        {
            MemberAccessExpressionSyntax m => m.Name,
            MemberBindingExpressionSyntax b => b.Name,
            _ => null,
        };

        // calls: and values: of constructors; `new D(x)` of a delegate type.
        private void Creation(IOperation? op, BaseObjectCreationExpressionSyntax syntax)
        {
            foreach (var rule in _rules)
            {
                var m = rule.Misuse!;
                switch (op)
                {
                    case IObjectCreationOperation { Constructor: { } ctor } created:
                        foreach (var p in m.Calls)
                            if (p.Kind == MemberKind.Constructor && SymbolMatch.Matches(p, ctor)) Report(rule, syntax.GetLocation(), $"creates {_ctx.Name(ctor.ContainingType)}");
                        foreach (var v in m.Values)
                            if (v.Member.Kind == MemberKind.Constructor && SymbolMatch.Matches(v.Member, ctor)) Arguments(rule, v, created, ctor);
                        break;
                    case IDelegateCreationOperation { Type: { } type } d when syntax.ArgumentList is { Arguments.Count: 1 } list:
                        foreach (var v in m.Values)
                        {
                            if (v.Member.Kind == MemberKind.Constructor && SymbolMatch.MetadataName(type) == v.Member.TypeName && v.Args.Contains(0))
                                Value(rule, v, d.Target, null, list.Arguments[0].GetLocation(), $"given to new {_ctx.Name(type)}(...)");
                        }
                        break;
                }
            }
        }

        private void Arguments(RuleModel rule, ValueCheck check, IOperation call, IMethodSymbol member)
        {
            foreach (var ordinal in check.Args)
            {
                if (SinkConditions.ArgumentValue(call, ordinal) is not { } value) continue;
                var argument = value.Parent is IArgumentOperation a ? a.Syntax : value.Syntax;
                Value(rule, check, value, null, argument.GetLocation(), $"given to {_ctx.Name(member)}");
            }
        }

        // values: of properties (an assignment, also `+=` and an object initializer's).
        private void Assignment(IAssignmentOperation assignment)
        {
            if (SinkConditions.Unwrap(assignment.Target) is not IPropertyReferenceOperation target) return;
            foreach (var rule in _rules)
            {
                foreach (var v in rule.Misuse!.Values)
                {
                    if (v.Member.Kind != MemberKind.PropertySet || !SymbolMatch.Matches(v.Member, target.Property)) continue;
                    var at = assignment.Syntax;
                    if (v.AtObject && target.Instance is IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ImplicitReceiver })
                    {
                        for (var o = assignment.Parent; o != null; o = o.Parent)
                        {
                            if (o is IObjectCreationOperation creation)
                            {
                                at = creation.Syntax;
                                break;
                            }
                        }
                    }
                    Value(rule, v, assignment.Value, target, at.GetLocation(), $"assigned to {_ctx.Name(target.Property)}");
                }
            }
        }

        /// A value check at one site: the value (the object written to for `with` / `without`) and where to report.
        private void Value(RuleModel rule, ValueCheck check, IOperation value, IPropertyReferenceOperation? target, Location at, string where)
        {
            var facts = Facts(value);
            string? what = null;
            foreach (var candidate in Candidates(value, facts, 0))
            {
                if (check.AcceptsAll && candidate is IAnonymousFunctionOperation fn && AcceptsAll(fn.Body))
                {
                    what = "a certificate callback that accepts every certificate";
                    break;
                }
                if (check.Created.Count > 0 && candidate is IObjectCreationOperation { Type: { } type } && check.Created.Contains(SymbolMatch.MetadataName(type)))
                {
                    what = $"new {_ctx.Name(type)}";
                    break;
                }
            }
            if (what == null) return;
            if (check.With != null || check.Without != null)
            {
                var key = target == null ? null : facts.Key(target.Instance);
                if (check.With != null && (key == null || !SetTo(facts, key, check.With))) return;
                if (check.Without != null && key != null && SetTo(facts, key, check.Without)) return;
            }
            Report(rule, at, $"{what} {where}" + (check.With != null ? $" with {check.With.Property} {string.Join(" or ", check.With.Values)}" : ""));
        }

        /// Whether the object `key` has its property set to one of the enum members anywhere in the body.
        private static bool SetTo(BodyFacts facts, string key, PropertyValues property) =>
            facts.PropertyValues(key, property.Property).SelectMany(v => Candidates(v, facts, 0)).Any(c => IsMember(c, property.Values));

        private static bool IsMember(IOperation op, IReadOnlyList<string> names)
        {
            var type = op.Type is INamedTypeSymbol { ConstructedFrom.SpecialType: SpecialType.System_Nullable_T } nullable ? nullable.TypeArguments[0] : op.Type;
            var constant = Constant(op);
            if (type is not INamedTypeSymbol { TypeKind: TypeKind.Enum } || constant == null) return false;
            return names.Any(n => type.GetMembers(n).OfType<IFieldSymbol>().Any(f => f.HasConstantValue && Equals(f.ConstantValue, constant)));
        }

        private static object? Constant(IOperation? op)
        {
            for (; op != null; op = (op as IConversionOperation)?.Operand)
                if (op.ConstantValue.HasValue) return op.ConstantValue.Value;
            return null;
        }

        /// What a value may be: through conversions, a delegate creation's target, both branches of `?:` and `??`, and a
        /// local's assigned values (a local written another way is itself).
        private static IEnumerable<IOperation> Candidates(IOperation? op, BodyFacts facts, int depth)
        {
            while (true)
            {
                if (op is IConversionOperation c) op = c.Operand;
                else if (op is IDelegateCreationOperation d) op = d.Target;
                else break;
            }
            if (op == null || depth > 8) yield break;
            switch (op)
            {
                case IConditionalOperation conditional:
                    foreach (var v in Candidates(conditional.WhenTrue, facts, depth + 1)) yield return v;
                    foreach (var v in Candidates(conditional.WhenFalse, facts, depth + 1)) yield return v;
                    break;
                case ICoalesceOperation coalesce:
                    foreach (var v in Candidates(coalesce.Value, facts, depth + 1)) yield return v;
                    foreach (var v in Candidates(coalesce.WhenNull, facts, depth + 1)) yield return v;
                    break;
                case ILocalReferenceOperation local when facts.LocalValues(local.Local) is { } values:
                    foreach (var value in values)
                        foreach (var v in Candidates(value, facts, depth + 1)) yield return v;
                    break;
                default:
                    yield return op;
                    break;
            }
        }

        private BodyFacts Facts(IOperation op)
        {
            var root = op;
            while (root.Parent != null) root = root.Parent;
            if (!_facts.TryGetValue(root.Syntax, out var facts)) _facts[root.Syntax] = facts = new BodyFacts(root);
            return facts;
        }

        // calls: of properties (a read).
        private void Read(ExpressionSyntax syntax, SimpleNameSyntax name)
        {
            if (Bound(syntax) is not IPropertyReferenceOperation read) return;
            if (read.Parent is IAssignmentOperation assignment && assignment.Target == read && assignment is not ICompoundAssignmentOperation) return;
            foreach (var rule in _rules)
                foreach (var p in rule.Misuse!.Calls)
                    if (p.Kind == MemberKind.PropertyGet && SymbolMatch.Matches(p, read.Property))
                        Report(rule, name.GetLocation(), $"reads {_ctx.Name(read.Property)}");
        }

        // enum-values: the written member (a property or field, by its symbol or the name that binds to it) and the value.
        private void EnumValue(ExpressionSyntax target, ExpressionSyntax value, SyntaxNode at) =>
            EnumValue(Model.GetSymbolInfo(target, _ct).Symbol, value, at);

        private void EnumValue(ISymbol? member, ExpressionSyntax value, SyntaxNode at)
        {
            var type = member switch
            {
                IPropertySymbol p => p.Type,
                IFieldSymbol { IsConst: false } f => f.Type,   // a const is no setting: where it is written is
                _ => null,
            };
            if (type is INamedTypeSymbol { ConstructedFrom.SpecialType: SpecialType.System_Nullable_T } nullable) type = nullable.TypeArguments[0];
            if (type is not INamedTypeSymbol { TypeKind: TypeKind.Enum } enumType) return;
            var constant = Model.GetConstantValue(value, _ct);
            if (!constant.HasValue || constant.Value == null) return;
            var typeName = SymbolMatch.MetadataName(enumType);
            foreach (var rule in _rules)
            {
                foreach (var check in rule.Misuse!.EnumValues)
                {
                    if (check.Type != typeName) continue;
                    var safe = check.Safe.Any(n => enumType.GetMembers(n).OfType<IFieldSymbol>().Any(f => f.HasConstantValue && Equals(f.ConstantValue, constant.Value)));
                    if (safe) continue;
                    var named = enumType.GetMembers().OfType<IFieldSymbol>().FirstOrDefault(f => f.HasConstantValue && Equals(f.ConstantValue, constant.Value))?.Name
                        ?? constant.Value.ToString();
                    Report(rule, at.GetLocation(), $"sets {member!.Name} to {enumType.Name}.{named}");
                }
            }
        }

        // accepts-all-methods: a method or local function declaration.
        private void Method(SyntaxNode declaration, SyntaxToken identifier)
        {
            if (Model.GetDeclaredSymbol(declaration, _ct) is not IMethodSymbol { ReturnType.SpecialType: SpecialType.System_Boolean } method) return;
            var applicable = _rules.Where(r => r.Misuse!.AcceptsAllMethods is { } t && method.Parameters.Any(p => SymbolMatch.MetadataName(p.Type) == t)).ToList();
            if (applicable.Count == 0) return;
            var body = Model.GetOperation(declaration, _ct) switch
            {
                IMethodBodyOperation { BlockBody: { } block, ExpressionBody: null } => block,
                IMethodBodyOperation { BlockBody: null, ExpressionBody: { } expression } => expression,
                ILocalFunctionOperation { Body: { } block, IgnoredBody: null } => block,
                _ => null,
            };
            if (body == null || !AcceptsAll(body)) return;
            foreach (var rule in applicable)
                Report(rule, identifier.GetLocation(), $"{method.Name} accepts every certificate (every return is true)");
        }

        /// Every return of the body (not of nested lambdas or local functions) returns an always-true value, there is at
        /// least one, and the body throws nowhere.
        private static bool AcceptsAll(IBlockOperation body)
        {
            var returns = 0;
            var stack = new Stack<IOperation>();
            stack.Push(body);
            while (stack.Count > 0)
            {
                var op = stack.Pop();
                switch (op)
                {
                    case IThrowOperation:
                        return false;
                    case IReturnOperation r:
                        if (r.ReturnedValue == null || !AlwaysTrue(r.ReturnedValue, 0)) return false;
                        returns++;
                        break;
                    case IAnonymousFunctionOperation or ILocalFunctionOperation:
                        continue;
                }
                foreach (var child in op.ChildOperations) stack.Push(child);
            }
            return returns > 0;
        }

        private static bool AlwaysTrue(IOperation op, int depth)
        {
            while (op is IConversionOperation c) op = c.Operand;
            if (depth > 16) return false;
            if (op.ConstantValue is { HasValue: true, Value: true }) return true;
            return op switch
            {
                IBinaryOperation { OperatorKind: BinaryOperatorKind.ConditionalOr } or => AlwaysTrue(or.LeftOperand, depth + 1) || AlwaysTrue(or.RightOperand, depth + 1),
                IBinaryOperation { OperatorKind: BinaryOperatorKind.ConditionalAnd } and => AlwaysTrue(and.LeftOperand, depth + 1) && AlwaysTrue(and.RightOperand, depth + 1),
                IConditionalOperation { WhenFalse: { } whenFalse } ternary => AlwaysTrue(ternary.WhenTrue, depth + 1) && AlwaysTrue(whenFalse, depth + 1),
                _ => false,
            };
        }

        private void Report(RuleModel rule, Location at, string message) => _ctx.ReportMisuse(rule.RuleId, at, message);
    }
}
