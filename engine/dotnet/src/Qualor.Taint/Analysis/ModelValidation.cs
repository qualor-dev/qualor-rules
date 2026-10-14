using System.Collections;
using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// Model validation as a sanitizer (Task 31, decision R-12; models/README.md "Model validation"): the validation facts
/// of bound members (which rules a member's data annotations clean) and where validation is known to hold (sources.yml
/// (7)). The checks themselves (IsValid, TryValidateModel) and the entry facts are MethodAnalyzer.Validation.cs.
///
/// What an attribute cleans (learn.microsoft.com, System.ComponentModel.DataAnnotations), on a member of type string:
/// - [Range] with a numeric operand ("Specifies the numeric range constraints"; a string is converted to the operand
///   type first): every rule but those with `validation: never` (command-injection, ruling R-E34). The accepted text is
///   a number's in a loose sense: surrounding whitespace, a sign, group separators, an exponent, a trailing line break
///   or NUL, and with a `typeof` operand hex forms (" 5", "-5", "1,000", "1E+2", "0x10"). A range over another operand
///   type (a date) cleans nothing.
/// - [EnumDataType] of an enum: the same rules. It accepts names, numbers, spaces and commas ("Top, Middle", "3").
/// - [RegularExpression]: the rules whose metacharacters (a rule model's `validation:`) the pattern's alphabet
///   (RegexAlphabet: the pattern is held to the whole value, "an exact match") does not hold.
/// - Anything else ([EmailAddress], [Url], [Phone], [StringLength], [MaxLength], [MinLength], [Required], custom
///   attributes, IValidatableObject, FluentValidation): nothing.
/// Members of enum and number types are clean already (sources.yml's scalars). Several attributes all hold: their rules
/// are united. A member, parameter or type with a not-validated attribute ([ValidateNever]) is not validated.
internal sealed class ModelValidation
{
    /// The validated paths below a bound object: at most this many, AccessPath.MaxMembers deep.
    public const int MaxPaths = 32;

    private static readonly ConditionalWeakTable<System.Text.RegularExpressions.Regex, BitArray> Metacharacters = new();

    private readonly ValidationSources? _model;
    private readonly IReadOnlyList<(string Rule, System.Text.RegularExpressions.Regex Set)> _rules;
    private readonly string[] _allRules;
    private readonly Dictionary<ISymbol, string[]> _memberRules = new(SymbolEqualityComparer.Default);
    private readonly Dictionary<ITypeSymbol, List<(ImmutableArray<IPropertySymbol> Members, string[] Rules)>> _paths = new(SymbolEqualityComparer.Default);
    private readonly Dictionary<ISymbol, bool> _automatic = new(SymbolEqualityComparer.Default);
    private readonly HashSet<string> _apiAttributes, _notValidated, _keepsValidity, _holders;

    public ModelValidation(ValidationSources? model, IEnumerable<RuleModel> rules, string[] allRules)
    {
        _model = model;
        var ruleList = rules.ToList();
        _rules = ruleList.Where(r => r.ValidationMetacharacters != null).Select(r => (r.RuleId, r.ValidationMetacharacters!)).ToList();
        // `validation: never` (ruling R-E34): no attribute cleans the rule, [Range] and [EnumDataType] neither.
        var never = ruleList.Where(r => r.ValidationNever).Select(r => r.RuleId).ToHashSet(StringComparer.Ordinal);
        _allRules = allRules.Where(r => !never.Contains(r)).ToArray();
        _apiAttributes = new HashSet<string>(model?.ApiControllerAttributes ?? Array.Empty<string>(), StringComparer.Ordinal);
        _notValidated = new HashSet<string>(model?.NotValidatedAttributes ?? Array.Empty<string>(), StringComparer.Ordinal);
        _keepsValidity = new HashSet<string>(model?.KeepsValidity ?? Array.Empty<string>(), StringComparer.Ordinal);
        _holders = new HashSet<string>(model?.ModelStateHolders ?? Array.Empty<string>(), StringComparer.Ordinal);
    }

    public bool Enabled => _model != null;

    /// Whether an assignment of the suppress option (other than `= false`) is somewhere in the source (Scan).
    public bool Suppressed { get; private set; }

    /// Looks for what turns the automatic 400 off (by syntax, on the safe side): `x.SuppressModelStateInvalidFilter =
    /// <anything but false>` (an assignment or an object initializer's); any assignment of
    /// `InvalidModelStateResponseFactory` (the factory decides the response); and `Configure<ApiBehaviorOptions>(x)` given
    /// anything but a lambda (options bound from configuration may set the option there). Review M4.
    public void Scan(Compilation compilation, CancellationToken ct)
    {
        if (_model == null || Suppressed) return;
        foreach (var tree in compilation.SyntaxTrees)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var token in tree.GetRoot(ct).DescendantTokens())
            {
                if (!token.IsKind(SyntaxKind.IdentifierToken)) continue;
                if (token.ValueText == _model.SuppressOption || token.ValueText == _model.ResponseFactory)
                {
                    var name = token.Parent;
                    var target = name?.Parent is MemberAccessExpressionSyntax access && access.Name == name ? access : name as ExpressionSyntax;
                    if (target?.Parent is AssignmentExpressionSyntax assignment && assignment.Left == target
                        && !assignment.Right.IsKind(SyntaxKind.FalseLiteralExpression))
                        Suppressed = true;
                }
                else if (token.ValueText == _model.OptionsType && token.Parent?.Parent is TypeArgumentListSyntax { Parent: GenericNameSyntax { Identifier.ValueText: "Configure" } generic }
                    && (generic.Parent is MemberAccessExpressionSyntax m && m.Name == generic ? m.Parent : generic.Parent) is InvocationExpressionSyntax call
                    && call.ArgumentList.Arguments.Any(a => a.Expression is not LambdaExpressionSyntax and not AnonymousMethodExpressionSyntax))
                {
                    Suppressed = true;
                }
                if (Suppressed) return;
            }
        }
    }

    /// Whether validation holds in every run of this action: an [ApiController] attribute on its class, a base class or
    /// the assembly (the automatic HTTP 400), and the filter not suppressed.
    public bool IsAutomatic(IMethodSymbol action)
    {
        if (_model == null || Suppressed || action.ContainingType is not { } type) return false;
        type = type.OriginalDefinition;
        if (_automatic.TryGetValue(type, out var cached)) return cached;
        var result = Has(type.ContainingAssembly.GetAttributes(), _apiAttributes);
        for (var t = type; t != null && !result; t = t.BaseType) result = Has(t.GetAttributes(), _apiAttributes);
        _automatic[type] = result;
        return result;
    }

    /// `ModelState.IsValid` of the action (ModelState read on `this`).
    public bool IsValidity(IPropertyReferenceOperation property)
    {
        if (_model == null || !SymbolMatch.Matches(_model.IsValid, property.Property)) return false;
        var state = Unwrapped(property.Instance);
        return state is IPropertyReferenceOperation { Instance: IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ContainingTypeInstance } } read
            && _model.ModelState.Any(p => SymbolMatch.Matches(p, read.Property));
    }

    /// A read of a ModelStateDictionary (the action's, through any path: `ModelState`, `ViewData.ModelState`) used
    /// otherwise than by one of the members that keep validity (`keeps-validity`: reads, AddModelError) called or read on
    /// it in place: removed, cleared, marked, an entry taken, given to a call, held in a variable (review C2).
    public bool ChangesValidity(IPropertyReferenceOperation read)
    {
        if (_model == null || read.Type is not { } type || SymbolMatch.MetadataName(type) != _model.IsValid.TypeName) return false;
        return read.Parent switch
        {
            IPropertyReferenceOperation { Arguments.Length: 0 } use when ReferenceEquals(use.Instance, read) => !_keepsValidity.Contains(use.Property.Name),
            IInvocationOperation use when ReferenceEquals(use.Instance, read) => !_keepsValidity.Contains(use.TargetMethod.Name),
            _ => true,
        };
    }

    /// Whether a value of this type holds a ModelStateDictionary: one of `model-state-holders` or a type derived from one
    /// (ControllerContext and ViewContext from ActionContext; re-review RR-M1).
    public bool HoldsModelState(ITypeSymbol? type)
    {
        if (_holders.Count == 0) return false;
        for (var t = type; t != null; t = t.BaseType)
            if (_holders.Contains(SymbolMatch.MetadataName(t))) return true;
        return false;
    }

    /// A TryValidateModel call of the action (on `this`, the framework's method, not an override in the project).
    public bool IsTryValidate(IInvocationOperation call)
    {
        if (_model == null || SymbolKeys.InSource(call.TargetMethod) || call.Arguments.Length == 0) return false;
        if (Unwrapped(call.Instance) is not IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ContainingTypeInstance }) return false;
        return _model.TryValidate.Any(p => SymbolMatch.Matches(p, call.TargetMethod));
    }

    /// Whether a parameter, a property or its type is left out of validation. [ValidateNever] is inherited
    /// (`Inherited = true`): a base class's attribute counts, and so does an overridden property's.
    public bool NotValidated(ISymbol symbol)
    {
        if (Has(symbol.GetAttributes(), _notValidated)) return true;
        if (symbol is IPropertySymbol property)
            for (var o = property.OverriddenProperty; o != null; o = o.OverriddenProperty)
                if (Has(o.GetAttributes(), _notValidated)) return true;
        var type = symbol switch
        {
            IParameterSymbol p => p.Type,
            IPropertySymbol p => p.Type,
            _ => null,
        };
        return type != null && TypeNotValidated(SourceFinder.UnwrapNullable(type));
    }

    private bool TypeNotValidated(ITypeSymbol type)
    {
        for (var t = type; t != null; t = t.BaseType)
            if (Has(t.GetAttributes(), _notValidated)) return true;
        return false;
    }

    /// The rules a bound parameter's or property's own attributes clean (empty: none).
    public string[] RulesFor(ISymbol symbol)
    {
        if (_model == null) return Array.Empty<string>();
        symbol = symbol.OriginalDefinition;
        if (_memberRules.TryGetValue(symbol, out var cached)) return cached;
        var result = Compute(symbol);
        _memberRules[symbol] = result;
        return result;
    }

    private string[] Compute(ISymbol symbol)
    {
        var type = symbol switch
        {
            IParameterSymbol p => p.Type,
            IPropertySymbol p => p.Type,
            _ => null,
        };
        if (type?.SpecialType != SpecialType.System_String || NotValidated(symbol)) return Array.Empty<string>();
        var attributes = symbol.GetAttributes().AsEnumerable();
        // A property's overridden declarations carry attributes too.
        if (symbol is IPropertySymbol property)
            for (var o = property.OverriddenProperty; o != null; o = o.OverriddenProperty) attributes = attributes.Concat(o.GetAttributes());
        HashSet<string>? rules = null;
        foreach (var a in attributes)
        {
            if (a.AttributeClass is not { } c) continue;
            var name = SymbolMatch.MetadataName(c);
            IEnumerable<string>? cleans = null;
            if (name == _model!.Range && NumericRange(a)) cleans = _allRules;
            else if (name == _model.EnumDataType && a.ConstructorArguments is [{ Value: ITypeSymbol { TypeKind: TypeKind.Enum } }]) cleans = _allRules;
            else if (name == _model.RegularExpression && a.ConstructorArguments is [{ Value: string pattern }]) cleans = PatternRules(pattern);
            if (cleans != null) (rules ??= new HashSet<string>(StringComparer.Ordinal)).UnionWith(cleans);
        }
        return rules == null ? Array.Empty<string>() : rules.OrderBy(r => r, StringComparer.Ordinal).ToArray();
    }

    /// [Range(int, int)], [Range(double, double)], or [Range(typeof(T), min, max)] with a numeric T.
    private static bool NumericRange(AttributeData a)
    {
        if (a.AttributeConstructor is not { Parameters.Length: > 0 } ctor) return false;
        if (ctor.Parameters[0].Type.SpecialType is SpecialType.System_Int32 or SpecialType.System_Double) return true;
        return a.ConstructorArguments.Length > 0 && a.ConstructorArguments[0].Value is ITypeSymbol operand
            && operand.SpecialType is SpecialType.System_Byte or SpecialType.System_SByte or SpecialType.System_Int16 or SpecialType.System_UInt16
                or SpecialType.System_Int32 or SpecialType.System_UInt32 or SpecialType.System_Int64 or SpecialType.System_UInt64
                or SpecialType.System_Single or SpecialType.System_Double or SpecialType.System_Decimal;
    }

    /// The rules whose metacharacters a pattern's alphabet holds none of.
    public IEnumerable<string> PatternRules(string pattern)
    {
        if (RegexAlphabet.Of(pattern) is not { } alphabet) return Array.Empty<string>();
        var clean = new List<string>();
        foreach (var (rule, set) in _rules)
            if (!RegexAlphabet.Intersects(alphabet, Metacharacters.GetValue(set, RegexAlphabet.Materialize))) clean.Add(rule);
        return clean;
    }

    /// The validated member paths below an object of this type ("ValidationVisitor traverses the object graph"): each
    /// public instance property of a type of the project (its bases' too) with cleaning attributes, and recursively the
    /// properties of a property whose type is a class or struct of the project (not a collection: an element is not
    /// followed), up to AccessPath.MaxMembers members and MaxPaths paths.
    public IReadOnlyList<(ImmutableArray<IPropertySymbol> Members, string[] Rules)> Paths(ITypeSymbol type)
    {
        if (_model == null) return Array.Empty<(ImmutableArray<IPropertySymbol>, string[])>();
        type = SourceFinder.UnwrapNullable(type);
        if (_paths.TryGetValue(type, out var cached)) return cached;
        var list = new List<(ImmutableArray<IPropertySymbol>, string[])>();
        if (!TypeNotValidated(type)) Walk(type, ImmutableArray<IPropertySymbol>.Empty, list);
        _paths[type] = list;
        return list;
    }

    private void Walk(ITypeSymbol type, ImmutableArray<IPropertySymbol> prefix, List<(ImmutableArray<IPropertySymbol>, string[])> list)
    {
        if (!Complex(type) || prefix.Length >= AccessPath.MaxMembers) return;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var t = type as INamedTypeSymbol; t != null && SymbolKeys.InSource(t); t = t.BaseType)
        {
            foreach (var p in t.GetMembers().OfType<IPropertySymbol>())
            {
                if (list.Count >= MaxPaths) return;
                if (p.IsStatic || p.IsIndexer || p.DeclaredAccessibility != Accessibility.Public || !seen.Add(p.Name)) continue;
                if (NotValidated(p)) continue;
                var path = prefix.Add(p.OriginalDefinition);
                var rules = RulesFor(p);
                if (rules.Length > 0) list.Add((path, rules));
                var inner = SourceFinder.UnwrapNullable(p.Type);
                if (Complex(inner) && !prefix.Any(m => SymbolEqualityComparer.Default.Equals(m.Type, inner))
                    && !SymbolEqualityComparer.Default.Equals(inner, type)) Walk(inner, path, list);
            }
        }
    }

    /// A class or struct of the project that is no collection.
    private static bool Complex(ITypeSymbol type) =>
        type.TypeKind is TypeKind.Class or TypeKind.Struct && type.SpecialType == SpecialType.None && SymbolKeys.InSource(type)
        && !type.AllInterfaces.Any(i => i.SpecialType == SpecialType.System_Collections_IEnumerable);

    private static IOperation? Unwrapped(IOperation? op)
    {
        while (op is IConversionOperation c) op = c.Operand;
        return op;
    }

    /// An attribute of one of these classes, or of a class derived from one.
    private static bool Has(ImmutableArray<AttributeData> attributes, HashSet<string> names)
    {
        if (names.Count == 0) return false;
        foreach (var a in attributes)
            for (var c = a.AttributeClass; c != null; c = c.BaseType)
                if (names.Contains(SymbolMatch.MetadataName(c))) return true;
        return false;
    }
}
