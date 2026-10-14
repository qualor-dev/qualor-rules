using System.Collections;
using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;

namespace Qualor.Taint;

/// The characters a value accepted by a [RegularExpression] pattern may hold (Task 31, decision R-12; models/README.md
/// "Model validation"). RegularExpressionAttribute "searches for an exact match" (its Remarks): the pattern is held to the
/// whole value, anchored or not, so every character of an accepted value was consumed by one of the pattern's consuming
/// parts: a literal character, an escape naming one, a character class (`[...]`, `\d`, `\w`, `\s`, `\p{..}` and their
/// negations) or `.`. The alphabet is the union of what those parts admit, read with .NET's own Regex on each of the
/// 65,536 UTF-16 code units, both case-sensitively and case-insensitively (their union: a superset of what the pattern
/// admits under either case option; the culture-specific dotted and dotless i of tr/az are not read, and no rule's
/// metacharacters hold them). A part that matches no single character makes the pattern unread (a misread class).
///
/// - Not consuming: anchors, quantifiers, alternation, group syntax, and the contents of lookarounds (unless the pattern
///   also holds a backreference: a group captured inside a lookaround may then be consumed by it); a backreference
///   consumes what its group consumed (already counted). `\` and digits not starting a backreference read as an octal
///   character too (over-approximated).
/// - Not read (null: the pattern cleans nothing): the free-spacing option (`(?x)`, where whitespace and `#` change
///   meaning), conditionals (`(?(...)...)`), a construct this reader does not know, a pattern that does not parse.
internal static class RegexAlphabet
{
    private static readonly ConcurrentDictionary<string, BitArray?> Cache = new(StringComparer.Ordinal);

    private static readonly Regex Quantifier = new(@"\G\{[0-9]+(,[0-9]*)?\}", RegexOptions.CultureInvariant);

    /// The code units an accepted value may hold, or null when the pattern is not read.
    public static BitArray? Of(string pattern) => Cache.GetOrAdd(pattern, Compute);

    /// Whether the alphabet holds a character the set holds.
    public static bool Intersects(BitArray alphabet, BitArray set)
    {
        var a = new int[(alphabet.Length + 31) / 32];
        var b = new int[(set.Length + 31) / 32];
        alphabet.CopyTo(a, 0);
        set.CopyTo(b, 0);
        for (var i = 0; i < Math.Min(a.Length, b.Length); i++)
            if ((a[i] & b[i]) != 0) return true;
        return false;
    }

    /// The code units a single-character regular expression (`^(?:[...])$`) matches.
    public static BitArray Materialize(Regex singleCharacter)
    {
        var set = new BitArray(char.MaxValue + 1);
        for (var c = 0; c <= char.MaxValue; c++)
            if (singleCharacter.IsMatch(((char)c).ToString())) set[c] = true;
        return set;
    }

    private static BitArray? Compute(string pattern)
    {
        try
        {
            _ = new Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(1));
        }
        catch (ArgumentException)
        {
            return null;
        }
        var atoms = Atoms(pattern);
        if (atoms == null) return null;
        var alphabet = new BitArray(char.MaxValue + 1);
        if (atoms.Count == 0) return alphabet;
        var distinct = atoms.Distinct(StringComparer.Ordinal).ToList();
        Regex exact, folded;
        try
        {
            // Every part must be one character (a misread class would match none and hide what the pattern admits).
            foreach (var atom in distinct)
            {
                var one = new Regex(@"\A(?:" + atom + @")\z", RegexOptions.CultureInvariant);
                var any = false;
                for (var c = 0; c <= char.MaxValue && !any; c++) any = one.IsMatch(((char)c).ToString());
                if (!any) return null;
            }
            var alternation = @"\A(?:" + string.Join("|", distinct) + @")\z";
            // Both readings: case-insensitive adds the case partners of what a part names; case-sensitive keeps what a
            // negated class admits that its case-insensitive reading drops (`[^a-z]` admits `L`; review I2 c).
            exact = new Regex(alternation, RegexOptions.CultureInvariant);
            folded = new Regex(alternation, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }
        catch (ArgumentException)
        {
            return null;
        }
        for (var c = 0; c <= char.MaxValue; c++)
        {
            var text = ((char)c).ToString();
            if (exact.IsMatch(text) || folded.IsMatch(text)) alphabet[c] = true;
        }
        return alphabet;
    }

    /// The consuming parts of a pattern, each as a regular expression of one character; null when not read.
    internal static List<string>? Atoms(string p)
    {
        var all = new List<string>();
        var outside = new List<string>();
        var groups = new Stack<bool>(); // true: a lookaround
        var looking = 0;
        var backreference = false;
        var i = 0;
        while (i < p.Length)
        {
            var c = p[i];
            switch (c)
            {
                case '\\':
                {
                    if (i + 1 >= p.Length) return null;
                    var d = p[i + 1];
                    if ("bBAzZG".IndexOf(d) >= 0)
                    {
                        i += 2;
                    }
                    else if ("dDwWsS".IndexOf(d) >= 0)
                    {
                        Add(p.Substring(i, 2));
                        i += 2;
                    }
                    else if (d is 'p' or 'P')
                    {
                        var end = p.IndexOf('}', i);
                        if (end < 0 || i + 2 >= p.Length || p[i + 2] != '{') return null;
                        Add(p[i..(end + 1)]);
                        i = end + 1;
                    }
                    else if (d == 'k')
                    {
                        // \k<name> or \k'name': a backreference.
                        var close = i + 2 < p.Length && p[i + 2] == '\'' ? '\'' : '>';
                        var end = p.IndexOf(close, i + 3);
                        if (end < 0) return null;
                        backreference = true;
                        i = end + 1;
                    }
                    else if (d is '<' or '\'')
                    {
                        // `\<name>` and `\'name'`: the legacy forms of a named backreference (review I2 b); read as the
                        // character too.
                        backreference = true;
                        Add(Escape(d));
                        i += 2;
                    }
                    else if (char.IsAsciiDigit(d))
                    {
                        var j = i + 1;
                        while (j < p.Length && char.IsAsciiDigit(p[j])) j++;
                        var digits = p[(i + 1)..j];
                        if (d != '0') backreference = true;
                        // Read as an octal character as well (up to three octal digits).
                        var octal = 0;
                        var k = 0;
                        while (k < digits.Length && k < 3 && digits[k] is >= '0' and <= '7') octal = (octal * 8) + (digits[k++] - '0');
                        if (k > 0) Add(Escape((char)octal));
                        i = j;
                    }
                    else if (d == 'x')
                    {
                        if (i + 4 > p.Length) return null;
                        Add(p.Substring(i, 4));
                        i += 4;
                    }
                    else if (d == 'u')
                    {
                        if (i + 6 > p.Length) return null;
                        Add(p.Substring(i, 6));
                        i += 6;
                    }
                    else if (d == 'c')
                    {
                        if (i + 3 > p.Length) return null;
                        Add(p.Substring(i, 3));
                        i += 3;
                    }
                    else
                    {
                        Add(p.Substring(i, 2));
                        i += 2;
                    }
                    break;
                }
                case '[':
                {
                    var end = ClassEnd(p, i);
                    if (end < 0) return null;
                    Add(p[i..(end + 1)]);
                    i = end + 1;
                    break;
                }
                case '(':
                {
                    if (i + 1 < p.Length && p[i + 1] == '?')
                    {
                        if (i + 2 >= p.Length) return null;
                        var e = p[i + 2];
                        if (e == '#')
                        {
                            var end = p.IndexOf(')', i);
                            if (end < 0) return null;
                            i = end + 1;
                        }
                        else if (e is ':' or '>')
                        {
                            Open(false);
                            i += 3;
                        }
                        else if (e is '=' or '!')
                        {
                            Open(true);
                            i += 3;
                        }
                        else if (e == '<' && i + 3 < p.Length && p[i + 3] is '=' or '!')
                        {
                            Open(true);
                            i += 4;
                        }
                        else if (e is '<' or '\'')
                        {
                            // A named or balancing group.
                            var close = e == '<' ? '>' : '\'';
                            var end = p.IndexOf(close, i + 3);
                            if (end < 0) return null;
                            Open(false);
                            i = end + 1;
                        }
                        else if (e == '(')
                        {
                            return null; // a conditional
                        }
                        else
                        {
                            // Inline options: (?imnsx-imnsx) or (?imnsx-imnsx:...).
                            var j = i + 2;
                            var on = true;
                            while (j < p.Length && "imnsx-".IndexOf(p[j]) >= 0)
                            {
                                if (p[j] == '-') on = false;
                                else if (p[j] == 'x' && on) return null;
                                j++;
                            }
                            if (j >= p.Length) return null;
                            if (p[j] == ':') Open(false);
                            else if (p[j] != ')') return null;
                            i = j + 1;
                        }
                    }
                    else
                    {
                        Open(false);
                        i++;
                    }
                    break;
                }
                case ')':
                    if (groups.Count == 0) return null;
                    if (groups.Pop()) looking--;
                    i++;
                    break;
                case '.':
                    Add(@"[\s\S]");
                    i++;
                    break;
                case '|' or '^' or '$' or '*' or '+' or '?':
                    i++;
                    break;
                case '{':
                {
                    var q = Quantifier.Match(p, i);
                    if (q.Success)
                    {
                        i += q.Length;
                    }
                    else
                    {
                        Add(@"\{");
                        i++;
                    }
                    break;
                }
                default:
                    Add(Escape(c));
                    i++;
                    break;
            }
        }
        if (groups.Count != 0) return null;
        return backreference ? all : outside;

        void Open(bool lookaround)
        {
            groups.Push(lookaround);
            if (lookaround) looking++;
        }

        void Add(string atom)
        {
            all.Add(atom);
            if (looking == 0) outside.Add(atom);
        }
    }

    private static string Escape(char c) => c switch
    {
        _ when char.IsAsciiLetterOrDigit(c) => c.ToString(),
        _ => "\\u" + ((int)c).ToString("X4", System.Globalization.CultureInfo.InvariantCulture),
    };

    /// The index of the `]` that ends the class opening at `start`, or -1: a `]` right after `[` or `[^` is literal, an
    /// escape takes the next character, and a subtraction (`-[...]`, the `-` not escaped: review I2 a) holds a nested
    /// class.
    private static int ClassEnd(string p, int start)
    {
        var j = start + 1;
        if (j < p.Length && p[j] == '^') j++;
        if (j < p.Length && p[j] == ']') j++;
        var dash = false;
        while (j < p.Length)
        {
            var ch = p[j];
            if (ch == '\\')
            {
                j += 2;
                dash = false;
                continue;
            }
            var afterDash = dash;
            dash = ch == '-';
            if (ch == '[' && afterDash)
            {
                var inner = ClassEnd(p, j);
                if (inner < 0) return -1;
                j = inner + 1;
                continue;
            }
            if (ch == ']') return j;
            j++;
        }
        return -1;
    }

    /// For diagnostics: the alphabet's ASCII part as text.
    internal static string Ascii(BitArray alphabet)
    {
        var text = new StringBuilder();
        for (var c = 0x20; c < 0x7F; c++) if (alphabet[c]) text.Append((char)c);
        return text.ToString();
    }
}
