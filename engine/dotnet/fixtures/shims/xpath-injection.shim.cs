// Shim for the engine harness: xpath-injection
global using System.Text;

// The fixture calls Retry.Run with a name and a lambda; the class is a project helper it does not declare.
public static class Retry
{
    public static void Run(string name, Delegate action) { }
}

public class TitleVariable : System.Xml.Xsl.IXsltContextVariable
{
    public TitleVariable(string title) { }
    public bool IsLocal => false;
    public bool IsParam => false;
    public System.Xml.XPath.XPathResultType VariableType => System.Xml.XPath.XPathResultType.String;
    public object Evaluate(System.Xml.Xsl.XsltContext xsltContext) => null;
}
