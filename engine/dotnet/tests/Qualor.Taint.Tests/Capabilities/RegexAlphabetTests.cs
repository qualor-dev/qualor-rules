namespace Qualor.Taint.Tests.Capabilities;

/// The characters a [RegularExpression] pattern admits (Task 31; RegexAlphabet): the union of what its consuming parts
/// match, case-insensitively, the pattern held to the whole value.
public sealed class RegexAlphabetTests
{
    private static string Ascii(string pattern) => RegexAlphabet.Ascii(RegexAlphabet.Of(pattern)!);

    [Theory]
    [InlineData("^[a-c]+$", "ABCabc")]                       // a class, case-insensitive
    [InlineData("[a-c]+", "ABCabc")]                         // the same without anchors (an exact match either way)
    [InlineData(@"^\d{3}-\d{4}$", "-0123456789")]            // escapes of classes, a quantifier, a literal
    [InlineData(@"^[0-9a-f]{32}$", "0123456789ABCDEFabcdef")]
    [InlineData(@"^(?:ab|cd)?$", "ABCDabcd")]                // a group, alternation
    [InlineData(@"^(?<word>x)\k<word>$", "Xx")]             // a named group and its backreference
    [InlineData(@"^[a-z-[aeiou]]$", "BCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz")] // class subtraction
    [InlineData(@"^a(?=b)$", "Aa")]                           // a lookahead consumes nothing
    [InlineData(@"^a(?<!b)$", "Aa")]                          // nor a lookbehind
    [InlineData(@"^\x41B\047$", "'ABab")]               // hex, Unicode and octal escapes
    [InlineData(@"^\.\{x{2}$", ".Xx{")]                     // escaped metacharacters; `{` that starts a quantifier
    [InlineData(@"^a{b$", "ABab{")]                          // a `{` that does not
    [InlineData(@"^(?i)a$", "Aa")]                            // inline options other than x
    [InlineData(@"^[]a]$", "A]a")]                            // a `]` first in a class is literal
    [InlineData(@"^$", "")]                                   // only the empty value
    public void The_alphabet_is_what_the_consuming_parts_admit(string pattern, string ascii) => Assert.Equal(ascii, Ascii(pattern));

    /// `.` admits every character (also a line break under (?s)); a backreference to a group captured in a lookaround
    /// consumes what the lookaround matched, so the lookaround's parts count then.
    [Fact]
    public void A_dot_and_a_lookaround_read_by_a_backreference_count()
    {
        Assert.True(RegexAlphabet.Of(".")![(int)'\n']);
        Assert.Contains("'", Ascii(@"^(?=(['a]))\1$"));
        Assert.DoesNotContain("'", Ascii(@"^(?=['a])a$"));
    }

    /// Review I2: an escaped dash before `[` starts no subtraction (`[a-z\-[]` is a class, then `'`, `[0-9]`, `]`); the
    /// legacy backreference forms `\<name>` and `\'name'` read a group captured in a lookahead; a negated class keeps the
    /// letters its case-sensitive reading admits (`[^a-z...]` admits upper case). Each pattern is checked against .NET's
    /// Regex first.
    [Theory]
    [InlineData(@"^[a-z\-[]'[0-9]]$", "a'5]", '\'')]
    [InlineData(@"^(?=(?<q>'))\<q>$", "'", '\'')]
    [InlineData(@"^(?=(?'q''))\'q'$", "'", '\'')]
    [InlineData(@"^[^a-z\W_\u0080-\uFFFF]+$", "HOST", 'H')]
    public void The_alphabet_holds_what_dotnet_accepts(string pattern, string accepted, char character)
    {
        var match = System.Text.RegularExpressions.Regex.Match(accepted, pattern);
        Assert.True(match.Success && match.Index == 0 && match.Length == accepted.Length, "not accepted by .NET: " + pattern);
        var alphabet = RegexAlphabet.Of(pattern);
        Assert.NotNull(alphabet);
        Assert.True(alphabet![character], $"alphabet of {pattern} misses {character}");
    }

    [Theory]
    [InlineData("(?x) ^ a $")]          // free-spacing: whitespace and # change meaning
    [InlineData("(?x:a b)")]
    [InlineData("^(?(a)a|b)$")]         // a conditional
    [InlineData("^[a-$")]               // does not parse
    [InlineData("(a")]
    public void Some_patterns_are_not_read(string pattern) => Assert.Null(RegexAlphabet.Of(pattern));
}
