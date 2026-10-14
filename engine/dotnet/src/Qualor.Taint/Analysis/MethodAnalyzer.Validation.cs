using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// Model validation as a sanitizer (Task 31, decision R-12; models/README.md "Model validation"), on the guard machinery
/// of Tasks 11 and 21. In an action or Razor Pages handler, the values model binding validated are its source parameters
/// (their own attributes: top-level nodes) and the member paths below them and below the bound properties of `this`
/// (ModelValidation.Paths). At the entry:
/// - in an [ApiController] action (validation holds in every run: ModelValidation.IsAutomatic), each validated
///   parameter is cleaned for its rules and each validated path gets a member fact that cleans its rules;
/// - otherwise each validated path gets a pending member fact (Pending: the body's root operation), which a write or a
///   call that may change the object ends like any member fact (MethodAnalyzer.Guards.cs).
/// On the branch where `ModelState.IsValid` or `TryValidateModel(x)` is true (also `== true`, `!= false`, through `!`,
/// `&&` and `||`), the pending facts still held clean their rules, the validated parameters never assigned in the body
/// are cleaned, and TryValidateModel's model gets the facts of its own paths.
internal sealed partial class MethodAnalyzer
{
    /// The validated paths of the analysed action and the rules each cleans; null when the body is no action.
    private Dictionary<AccessPath, string[]>? _validatedPaths;

    /// The validated parameters of the analysed action and the rules each cleans.
    private List<(IParameterSymbol Parameter, string[] Rules)>? _validatedParameters;

    /// Seeds the entry state of an action's body with its validation facts.
    private void SeedValidation(TaintState entry)
    {
        var validation = _ctx.Validation;
        if (!validation.Enabled || _body.Method is not { } method) return;
        if (!_ctx.Sources.IsAction(method) && !_ctx.Sources.IsPageHandler(method)) return;
        var automatic = validation.IsAutomatic(method);
        var pending = ImmutableHashSet.Create(_cfg.OriginalOperation);
        _validatedPaths = new Dictionary<AccessPath, string[]>();
        _validatedParameters = new List<(IParameterSymbol, string[])>();
        foreach (var p in method.Parameters)
        {
            if (!_ctx.Sources.IsSourceParameter(p) || validation.NotValidated(p)) continue;
            var rules = validation.RulesFor(p);
            if (rules.Length > 0)
            {
                _validatedParameters.Add((p, rules));
                if (automatic && entry.Get(p) is { Any: true } value) entry.Set(p, value.CleanedFor(rules));
            }
            foreach (var (members, memberRules) in validation.Paths(p.Type)) Seed(p, p.Type, members, memberRules);
        }
        // Bound properties of a controller or page model ("Controller properties", "Page model properties").
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var t = method.ContainingType; t != null && SymbolKeys.InSource(t); t = t.BaseType)
        {
            foreach (var property in t.GetMembers().OfType<IPropertySymbol>())
            {
                if (!seen.Add(property.Name) || !_ctx.Sources.IsBoundProperty(property) || validation.NotValidated(property)) continue;
                var own = ImmutableArray.Create(property.OriginalDefinition);
                if (validation.RulesFor(property) is { Length: > 0 } rules) Seed(AccessPath.This, method.ContainingType, own, rules);
                foreach (var (members, memberRules) in validation.Paths(property.Type))
                    if (members.Length < AccessPath.MaxMembers) Seed(AccessPath.This, method.ContainingType, own.AddRange(members), memberRules);
            }
        }

        void Seed(object root, ITypeSymbol rootType, ImmutableArray<IPropertySymbol> members, string[] rules)
        {
            // At most half the member facts a state holds: the guards of the body keep room (MemberFacts.MaxFacts).
            if (_validatedPaths!.Count >= MemberFacts.MaxFacts / 2) return;
            if (Path(root, rootType, members) is not { } path || !CanHold(path)) return;
            _validatedPaths![path] = rules;
            entry.AddFact(automatic
                ? new MemberFact(path, false, rules.ToImmutableHashSet(), ImmutableHashSet<IOperation>.Empty)
                : new MemberFact(path, false, ImmutableHashSet<string>.Empty, pending));
        }
    }

    /// The access path of `root.M1...Mn` (as PathOf builds it for a read).
    private static AccessPath? Path(object root, ITypeSymbol rootType, ImmutableArray<IPropertySymbol> members)
    {
        if (members.Length == 0 || members.Length > AccessPath.MaxMembers) return null;
        var types = new List<ITypeSymbol>(members.Length + 1);
        if (ReferenceEquals(root, AccessPath.This) || MemberFacts.IsChangeable(rootType)) types.Add(rootType);
        foreach (var m in members)
            if (MemberFacts.IsChangeable(m.Type)) types.Add(m.Type);
        return new AccessPath(root, members.CastArray<ISymbol>(), types.ToImmutableArray());
    }

    /// A validity check in a condition: `ModelState.IsValid` or `TryValidateModel(...)` of the action.
    private bool IsValidityCheck(IOperation op)
    {
        while (op is IConversionOperation c) op = c.Operand;
        return op switch
        {
            IPropertyReferenceOperation p => _ctx.Validation.IsValidity(p),
            IInvocationOperation call => _ctx.Validation.IsTryValidate(call),
            _ => false,
        };
    }

    /// On this branch the action's model state is valid: the pending validation facts still held clean their rules and
    /// the validated parameters assigned nowhere in the body are clean.
    private void Validated(TaintState state, ref TaintState? refined)
    {
        if (_validatedPaths == null || _validatedParameters == null) return;
        var marker = _cfg.OriginalOperation;
        foreach (var fact in (refined ?? state).Facts)
        {
            if (!fact.Pending.Contains(marker) || !_validatedPaths.TryGetValue(fact.Path, out var rules)) continue;
            refined ??= state.Clone();
            refined.AddFact(new MemberFact(fact.Path, false, rules.ToImmutableHashSet(), ImmutableHashSet<IOperation>.Empty));
        }
        foreach (var (p, rules) in _validatedParameters)
        {
            if (!NeverAssigned(p)) continue;
            var current = (refined ?? state).Get(p);
            if (!current.Any) continue;
            refined ??= state.Clone();
            refined.Set(p, current.CleanedFor(rules));
        }
    }

    /// TryValidateModel(model) returned true: besides the model state, the model's validated paths hold (on whatever
    /// object it is: a bound parameter, a property, a local built in the action).
    private void TryValidated(IInvocationOperation call, TaintState state, ref TaintState? refined)
    {
        Validated(state, ref refined);
        var model = Unwrapped(call.Arguments[0].Value);
        object? root;
        ImmutableArray<IPropertySymbol> prefix;
        ITypeSymbol? rootType;
        switch (model)
        {
            case ILocalReferenceOperation l:
                (root, rootType, prefix) = (l.Local, l.Local.Type, ImmutableArray<IPropertySymbol>.Empty);
                break;
            case IParameterReferenceOperation p:
                (root, rootType, prefix) = (p.Parameter, p.Parameter.Type, ImmutableArray<IPropertySymbol>.Empty);
                break;
            case IPropertyReferenceOperation { Instance: IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ContainingTypeInstance } i, Arguments.Length: 0 } p:
                (root, rootType, prefix) = (AccessPath.This, i.Type, ImmutableArray.Create(p.Property.OriginalDefinition));
                break;
            default:
                return;
        }
        if (rootType == null || model.Type == null) return;
        foreach (var (members, rules) in _ctx.Validation.Paths(model.Type))
        {
            if (prefix.Length + members.Length > AccessPath.MaxMembers) continue;
            if (Path(root, rootType, prefix.AddRange(members)) is not { } path || !CanHold(path)) continue;
            refined ??= state.Clone();
            refined.AddFact(new MemberFact(path, false, rules.ToImmutableHashSet(), ImmutableHashSet<IOperation>.Empty));
        }
    }

    /// Whether a parameter keeps the value it was bound with: assigned nowhere in the body (nor as a ref or out argument,
    /// nor by a lambda or local function of the method).
    private bool NeverAssigned(IParameterSymbol parameter)
    {
        if (_assignments == null) Assignments(parameter);
        if (_assignments!.ContainsKey(parameter)) return false;
        _nestedEffects ??= NestedEffects();
        return !_nestedEffects.Contains(parameter);
    }

    /// `check == c` or `check != c` with a bool constant c and a validity check: the check's outcome on this branch.
    private bool? ValidityOutcome(IBinaryOperation equality, bool outcome, out IOperation? check)
    {
        check = null;
        foreach (var (a, b) in new[] { (equality.LeftOperand, equality.RightOperand), (equality.RightOperand, equality.LeftOperand) })
        {
            if (!IsValidityCheck(a) || Unwrapped(b).ConstantValue is not { HasValue: true, Value: bool constant }) continue;
            check = a;
            var equal = (equality.OperatorKind == BinaryOperatorKind.Equals) == outcome;
            return equal ? constant : !constant;
        }
        return null;
    }
}
