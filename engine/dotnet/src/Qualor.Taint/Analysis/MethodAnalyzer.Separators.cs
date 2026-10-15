using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Qualor.Taint;

/// A value checked for directory separators (Task 35, lever c; models/README.md, "Guards in project code"): where a
/// search of a string or a span of char for separators found none, the value is one path segment, as Path.GetFileName
/// leaves it, and clean for the rules that sanitizer is a sanitizer of (`..` is such a segment too, the same reach).
///
/// The searches: `IndexOf` and `IndexOfAny` (System.String's, and MemoryExtensions' on a span, `AsSpan()` of the value
/// too) compared with a constant so that the branch admits no index of a match (`>= 0` false, `< 0` true, `== -1`),
/// and `Contains` (`ContainsAny`) false. The separators searched for: the constants '/' and '\', a string constant's
/// characters, Path.DirectorySeparatorChar and AltDirectorySeparatorChar, and Path.GetInvalidFileNameChars() (which holds
/// the platform's separators; GetInvalidPathChars does not), given in place (a char argument, an array or collection
/// expression of them, a string constant). IndexOf and Contains look for one character (a char, or a string constant of
/// one character: a longer one is a substring, which says nothing of each character); a search from a start index or of
/// a count is no check of the whole value.
///
/// Both separators of a platform that has two must be absent (Windows: '\' and '/'; elsewhere '/'): one search may find
/// both, or two searches each one, before a branch where the value is unchanged. Each search records a must-hold fact on
/// the value's local or parameter (a path with no member: an assignment of the variable ends it, a join keeps it only
/// where every predecessor has it), one per separator class, and the value is cleaned where both hold:
/// - Backslash: '\' or Path.DirectorySeparatorChar (Windows' own; elsewhere the slash);
/// - Slash: '/' or Path.AltDirectorySeparatorChar (Windows' other separator, the only one elsewhere).
/// A value with no separator may still be `..`, or on Windows a drive-relative `C:name` (the check names no volume
/// separator; BACKLOG.md `csharp.path-traversal#dotdot-segment`).
internal sealed partial class MethodAnalyzer
{
    /// The separator classes a search looked for.
    [Flags]
    private enum Separators
    {
        None = 0,
        Backslash = 1,
        Slash = 2,
        Both = Backslash | Slash,
    }

    /// The pseudo rules a separator fact holds (never a rule id: a fact on a path with no member cleans no read).
    private const string NoBackslash = "\u0001separator:backslash";
    private const string NoSlash = "\u0001separator:slash";

    private string[]? _segmentRules;

    /// `IndexOf(...)`/`IndexOfAny(...)` compared with a constant, on the branch with this outcome.
    private void IndexComparison(IBinaryOperation relation, bool outcome, TaintState state, ref TaintState? refined)
    {
        var left = Unwrapped(relation.LeftOperand);
        var right = Unwrapped(relation.RightOperand);
        var kind = relation.OperatorKind;
        IInvocationOperation? call;
        int bound;
        if (left is IInvocationOperation l && right.ConstantValue is { HasValue: true, Value: int r })
        {
            call = l;
            bound = r;
        }
        else if (right is IInvocationOperation rc && left.ConstantValue is { HasValue: true, Value: int lc })
        {
            call = rc;
            bound = lc;
            kind = Flipped(kind);
        }
        else
        {
            return;
        }
        if (!NoMatch(kind, bound, outcome) || SeparatorSearch(call, "IndexOf", "IndexOfAny") is not { } search) return;
        SeparatorsAbsent(search.Value, search.Found, state, ref refined);

        static BinaryOperatorKind Flipped(BinaryOperatorKind k) => k switch
        {
            BinaryOperatorKind.LessThan => BinaryOperatorKind.GreaterThan,
            BinaryOperatorKind.LessThanOrEqual => BinaryOperatorKind.GreaterThanOrEqual,
            BinaryOperatorKind.GreaterThan => BinaryOperatorKind.LessThan,
            BinaryOperatorKind.GreaterThanOrEqual => BinaryOperatorKind.LessThanOrEqual,
            _ => k,
        };
    }

    /// Whether `index kind bound` having `outcome` admits no index of a match (every index >= 0 gives the other outcome):
    /// the search found nothing (-1).
    private static bool NoMatch(BinaryOperatorKind kind, int bound, bool outcome)
    {
        // The comparisons are intervals or (in)equalities: these points decide them for every index >= 0.
        foreach (var i in new long[] { 0, Math.Max(bound - 1L, 0), Math.Max(bound, 0), Math.Max(bound + 1L, 0), int.MaxValue })
        {
            bool? holds = kind switch
            {
                BinaryOperatorKind.LessThan => i < bound,
                BinaryOperatorKind.LessThanOrEqual => i <= bound,
                BinaryOperatorKind.GreaterThan => i > bound,
                BinaryOperatorKind.GreaterThanOrEqual => i >= bound,
                BinaryOperatorKind.Equals => i == bound,
                BinaryOperatorKind.NotEquals => i != bound,
                _ => null,
            };
            if (holds == null || holds == outcome) return false;
        }
        return true;
    }

    /// `x.Contains(c)` (ContainsAny) false: x holds none of what it looked for.
    private void ContainsCheck(IInvocationOperation call, bool outcome, TaintState state, ref TaintState? refined)
    {
        if (outcome || SeparatorSearch(call, "Contains", "ContainsAny") is not { } search) return;
        SeparatorsAbsent(search.Value, search.Found, state, ref refined);
    }

    /// A search of System.String or MemoryExtensions named one of `names`: the value searched and the separators looked
    /// for; null when it is none or looks for no separator.
    private static (IOperation Value, Separators Found)? SeparatorSearch(IInvocationOperation call, string name, string anyName)
    {
        var method = call.TargetMethod;
        if (method.Name != name && method.Name != anyName) return null;
        var type = method.ContainingType;
        IOperation? value;
        IEnumerable<IOperation> sought;
        if (type?.SpecialType == SpecialType.System_String && !method.IsStatic && call.Instance != null)
        {
            value = call.Instance;
            sought = call.Arguments.Select(a => a.Value);
        }
        else if (type != null && SymbolMatch.MetadataName(type) == "System.MemoryExtensions" && method.IsStatic && call.Arguments.Length >= 2)
        {
            value = SpanOf(call.Arguments[0].Value);
            sought = call.Arguments.Skip(1).Select(a => a.Value);
        }
        else
        {
            return null;
        }
        if (value == null) return null;
        // IndexOf and Contains look for one character or a substring; IndexOfAny and ContainsAny for any of a set.
        var any = method.Name == anyName;
        // A comparison given must be ordinal (review I1): a culture's comparison treats a separator followed by a
        // combining mark as one text element and does not find it. string.IndexOf(string) without one compares by the
        // current culture; Contains(string), the char overloads, IndexOfAny and the span searches without one are
        // ordinal.
        var comparison = call.Arguments.Select(a => Unwrapped(a.Value)).FirstOrDefault(IsStringComparison);
        if (comparison != null && comparison.ConstantValue is not { HasValue: true, Value: (int)StringComparison.Ordinal or (int)StringComparison.OrdinalIgnoreCase })
            return null;
        if (comparison == null && method.Name == "IndexOf" && type?.SpecialType == SpecialType.System_String
            && method.Parameters.Length > 0 && method.Parameters[0].Type.SpecialType == SpecialType.System_String)
            return null;
        var found = Separators.None;
        foreach (var s in sought)
        {
            var soughtType = Unwrapped(s).Type;
            if (IsStringComparison(Unwrapped(s))) continue;
            if (soughtType is { TypeKind: TypeKind.Enum }) return null;
            // A start index or a count searches part of the value only.
            if (soughtType is { SpecialType: >= SpecialType.System_SByte and <= SpecialType.System_UInt64 }) return null;
            // A substring of more than one character says nothing of each of them.
            if (!any && Unwrapped(s).ConstantValue is { HasValue: true, Value: string { Length: not 1 } }) return null;
            if (!any && soughtType?.SpecialType != SpecialType.System_Char && Unwrapped(s).ConstantValue is not { HasValue: true, Value: string }) return null;
            found |= SoughtSeparators(s);
        }
        return found == Separators.None ? null : (value, found);
    }

    private static bool IsStringComparison(IOperation op) =>
        op.Type is INamedTypeSymbol { TypeKind: TypeKind.Enum } e && SymbolMatch.MetadataName(e) == "System.StringComparison";

    /// The string a span searched was made of (`x.AsSpan()`, an implicit conversion of x), or null.
    private static IOperation? SpanOf(IOperation op)
    {
        op = Unwrapped(op);
        if (op is IInvocationOperation { TargetMethod: { Name: "AsSpan", IsStatic: true } asSpan, Arguments.Length: 1 } call
            && SymbolMatch.MetadataName(asSpan.ContainingType) == "System.MemoryExtensions")
            op = Unwrapped(call.Arguments[0].Value);
        return op.Type?.SpecialType == SpecialType.System_String ? op : null;
    }

    /// The separator classes a sought value names: a char or string constant, a separator field of Path,
    /// Path.GetInvalidFileNameChars(), an array or collection expression of such chars.
    private static Separators SoughtSeparators(IOperation op)
    {
        op = Unwrapped(op);
        if (op.ConstantValue is { HasValue: true, Value: char c }) return Of(c);
        if (op.ConstantValue is { HasValue: true, Value: string s })
        {
            var found = Separators.None;
            foreach (var ch in s) found |= Of(ch);
            return found;
        }
        switch (op)
        {
            case IFieldReferenceOperation { Field: { Name: "DirectorySeparatorChar" or "AltDirectorySeparatorChar" } field } when IsPath(field.ContainingType):
                return field.Name == "DirectorySeparatorChar" ? Separators.Backslash : Separators.Slash;
            case IInvocationOperation { TargetMethod: { Name: "GetInvalidFileNameChars", IsStatic: true } m, Arguments.Length: 0 } when IsPath(m.ContainingType):
                return Separators.Both;
            case IArrayCreationOperation { Initializer: { } initializer }:
                return Elements(initializer.ElementValues);
            case ICollectionExpressionOperation collection:
                return Elements(collection.Elements);
            default:
                return Separators.None;
        }

        static Separators Of(char ch) => ch switch { '\\' => Separators.Backslash, '/' => Separators.Slash, _ => Separators.None };

        static Separators Elements(ImmutableArray<IOperation> elements)
        {
            var found = Separators.None;
            foreach (var e in elements) found |= SoughtSeparators(e);
            return found;
        }

        static bool IsPath(INamedTypeSymbol? type) => type != null && SymbolMatch.MetadataName(type) == "System.IO.Path";
    }

    /// On this branch `value` (a local or parameter) holds none of `found`: record it; where both classes are known
    /// absent, the value is a single segment.
    private void SeparatorsAbsent(IOperation value, Separators found, TaintState state, ref TaintState? refined)
    {
        var symbol = Unwrapped(value) switch
        {
            ILocalReferenceOperation l => (ISymbol)l.Local,
            IParameterReferenceOperation p => p.Parameter,
            _ => null,
        };
        if (symbol == null) return;
        var path = new AccessPath(symbol, ImmutableArray<ISymbol>.Empty, ImmutableArray<ITypeSymbol>.Empty);
        var known = (refined ?? state).Fact(path)?.Rules ?? ImmutableHashSet<string>.Empty;
        var absent = known;
        if ((found & Separators.Backslash) != 0) absent = absent.Add(NoBackslash);
        if ((found & Separators.Slash) != 0) absent = absent.Add(NoSlash);
        if (absent.Count != known.Count)
        {
            refined ??= state.Clone();
            refined.AddFact(new MemberFact(path, false, absent, ImmutableHashSet<IOperation>.Empty));
        }
        if (absent.Contains(NoBackslash) && absent.Contains(NoSlash) && SegmentRules() is { Length: > 0 } rules) Clean(value, rules, state, ref refined);
    }

    /// The rules Path.GetFileName is a sanitizer of (a single segment).
    private string[] SegmentRules()
    {
        if (_segmentRules != null) return _segmentRules;
        var getFileName = Model()?.Compilation.GetTypeByMetadataName("System.IO.Path")?.GetMembers("GetFileName").OfType<IMethodSymbol>()
            .FirstOrDefault(m => m.Parameters.Length == 1 && m.Parameters[0].Type.SpecialType == SpecialType.System_String);
        return _segmentRules = getFileName == null ? Array.Empty<string>() : _ctx.Sinks.Sanitizes(getFileName, Access.Call);
    }
}
