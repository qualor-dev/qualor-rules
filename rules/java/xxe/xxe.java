package com.acme.imports;

import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXTransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import org.dom4j.DocumentHelper;
import org.dom4j.io.SAXReader;
import org.jdom2.input.SAXBuilder;
import org.jdom2.input.sax.XMLReaders;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.XMLReaderFactory;

// DOM: DocumentBuilderFactory.
class DomImports {
    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";

    Document plain(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        // ruleid: java.xxe
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(in);
    }

    Document chained(InputStream in) throws Exception {
        // ruleid: java.xxe
        return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(in);
    }

    Document withVar(InputStream in) throws Exception {
        var factory = DocumentBuilderFactory.newDefaultNSInstance();
        // ruleid: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    Document doctypeAllowed(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        // ruleid: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // setExpandEntityReferences only changes how entity references appear in the tree.
    Document notExpanded(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setExpandEntityReferences(false);
        factory.setXIncludeAware(false);
        // ruleid: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // External parameter entities are still resolved.
    Document generalOnly(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        // ruleid: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // Secure processing alone is not a portable restriction on a factory found by lookup.
    Document secureProcessingOnly(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        // ruleid: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // A setting made after the builder was created does not apply to it.
    Document tooLate(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // ruleid: java.xxe
        DocumentBuilder builder = factory.newDocumentBuilder();
        factory.setFeature(DISALLOW_DOCTYPE, true);
        return builder.parse(in);
    }

    Document disallowed(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    Document disallowedByConstant(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(DISALLOW_DOCTYPE, true);
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    Document disallowedInTry(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            factory.setFeature(DISALLOW_DOCTYPE, true);
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        }
        // ok: java.xxe
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(in);
    }

    Document externalEntitiesOff(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    Document externalAccessDenied(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    Document externalAccessDeniedByName(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // The built-in JDK factory denies external access once secure processing is set explicitly.
    Document builtInSecure(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newDefaultInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // A builder that only creates documents parses no XML.
    Document emptyDocument() throws Exception {
        // ok: java.xxe
        return DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
    }

    Document emptyDocumentFromVariable() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // ok: java.xxe
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();
        document.appendChild(document.createElement("export"));
        return document;
    }

    Document fromImplementation() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // ok: java.xxe
        return factory.newDocumentBuilder().getDOMImplementation().createDocument(null, "export", null);
    }

    Document parsedInTry(InputStream in) throws Exception {
        // ruleid: java.xxe
        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        try {
            return builder.parse(in);
        } finally {
            in.close();
        }
    }

    // The fixed order of the three features does not matter.
    Document featuresInOtherOrder(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // A builder handed to the caller is parsed with elsewhere.
    DocumentBuilder handedOut() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // todoruleid: java.xxe
        return factory.newDocumentBuilder();
    }

    // A builder of another library with the same method name.
    Document lookAlike(InputStream in) throws Exception {
        com.acme.imports.xml.Builders builders = new com.acme.imports.xml.Builders();
        // ok: java.xxe
        return builders.newDocumentBuilder().parse(in);
    }

    // The factory is set up by a helper method.
    Document hardenedByHelper(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        harden(factory);
        // todook: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // The feature name comes from a constant of a class in another file.
    Document foreignConstant(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(com.acme.imports.xml.Features.DISALLOW_DOCTYPE, true);
        // todook: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // A resolver that refuses every external entity.
    Document rejectingResolver(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // todook: java.xxe
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.setEntityResolver((publicId, systemId) -> {
            throw new java.io.IOException("external entities are not allowed");
        });
        return builder.parse(in);
    }

    // External access denied for the whole JVM.
    Document systemWide(InputStream in) throws Exception {
        System.setProperty("javax.xml.accessExternalDTD", "");
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // todook: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // A factory made by a helper method.
    Document fromHelper(InputStream in) throws Exception {
        DocumentBuilderFactory factory = newFactory();
        // todoruleid: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    private static void harden(DocumentBuilderFactory factory) throws ParserConfigurationException {
        factory.setFeature(DISALLOW_DOCTYPE, true);
    }

    private static DocumentBuilderFactory newFactory() {
        return DocumentBuilderFactory.newInstance();
    }
}

// A factory in a field.
class SharedFactory {
    private static final DocumentBuilderFactory FACTORY = DocumentBuilderFactory.newInstance();

    Document parse(InputStream in) throws Exception {
        // ruleid: java.xxe
        return FACTORY.newDocumentBuilder().parse(in);
    }
}

class HardenedSharedFactory {
    private static final DocumentBuilderFactory FACTORY = DocumentBuilderFactory.newInstance();

    static {
        try {
            FACTORY.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        } catch (ParserConfigurationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    Document parse(InputStream in) throws Exception {
        // ok: java.xxe
        return FACTORY.newDocumentBuilder().parse(in);
    }
}

class HardenedInConstructor {
    private final SAXParserFactory factory = SAXParserFactory.newInstance();

    HardenedInConstructor() throws Exception {
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    }

    void parse(InputStream in, DefaultHandler handler) throws Exception {
        // ok: java.xxe
        factory.newSAXParser().parse(in, handler);
    }
}

class HardenedInMethod {
    private final XMLInputFactory factory = XMLInputFactory.newInstance();

    void configure() {
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    }

    void read(InputStream in) throws Exception {
        // ok: java.xxe
        factory.createXMLStreamReader(in);
    }
}

// A field assigned in a constructor rather than where it is declared.
class AssignedInConstructor {
    private final DocumentBuilderFactory factory;

    AssignedInConstructor() {
        factory = DocumentBuilderFactory.newInstance();
    }

    Document parse(InputStream in) throws Exception {
        // todoruleid: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }
}

// SAX: SAXParserFactory, SAXParser and XMLReader.
class SaxImports {
    void plain(InputStream in, DefaultHandler handler) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        // ruleid: java.xxe
        SAXParser parser = factory.newSAXParser();
        parser.parse(in, handler);
    }

    void chained(InputStream in, DefaultHandler handler) throws Exception {
        // ruleid: java.xxe
        SAXParserFactory.newInstance().newSAXParser().parse(in, handler);
    }

    void readerFactory(InputStream in) throws Exception {
        XMLReader reader = XMLReaderFactory.createXMLReader();
        // ruleid: java.xxe
        reader.parse(new InputSource(in));
    }

    void disallowed(InputStream in, DefaultHandler handler) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ok: java.xxe
        factory.newSAXParser().parse(in, handler);
    }

    void parserProperty(InputStream in, DefaultHandler handler) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        // ok: java.xxe
        SAXParser parser = factory.newSAXParser();
        parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        parser.parse(in, handler);
    }

    void readerFeature(InputStream in) throws Exception {
        // ok: java.xxe
        XMLReader reader = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.parse(new InputSource(in));
    }

    void readerFactoryHardened(InputStream in) throws Exception {
        XMLReader reader = XMLReaderFactory.createXMLReader();
        reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        // ok: java.xxe
        reader.parse(new InputSource(in));
    }

    // The external DTD is still fetched: a blind request to the DOCTYPE's system id.
    void entitiesOffDtdOn(InputStream in) throws Exception {
        XMLReader reader = XMLReaderFactory.createXMLReader();
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        // ruleid: java.xxe
        reader.parse(new InputSource(in));
    }

    void boxedTrue(InputStream in, DefaultHandler handler) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
        // ok: java.xxe
        factory.newSAXParser().parse(in, handler);
    }

    void builtInSecureByName(InputStream in, DefaultHandler handler) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newDefaultInstance();
        factory.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);
        // ok: java.xxe
        factory.newSAXParser().parse(in, handler);
    }
}

// StAX: XMLInputFactory.
class StaxImports {
    void plain(InputStream in) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java.xxe
        XMLStreamReader reader = factory.createXMLStreamReader(in);
    }

    void events(InputStream in) throws Exception {
        // ruleid: java.xxe
        XMLEventReader reader = XMLInputFactory.newFactory().createXMLEventReader(in);
    }

    void dtdSupported(InputStream in) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newDefaultFactory();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, true);
        // ruleid: java.xxe
        factory.createXMLStreamReader(in);
    }

    void noDtd(InputStream in) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        // ok: java.xxe
        factory.createXMLStreamReader(in);
    }

    void noDtdBoxed(InputStream in) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty("javax.xml.stream.supportDTD", Boolean.FALSE);
        // ok: java.xxe
        factory.createXMLEventReader(in);
    }

    void noExternalEntities(InputStream in) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        // ok: java.xxe
        factory.createXMLStreamReader(in);
    }

    void noDtdConstantBoxed(InputStream in) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
        // ok: java.xxe
        factory.createXMLStreamReader(in);
    }

    void noDtdByName(InputStream in) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty("javax.xml.stream.supportDTD", false);
        // ok: java.xxe
        factory.createXMLStreamReader(in);
    }

    void noExternalEntitiesBoxed(InputStream in) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
        // ok: java.xxe
        factory.createXMLStreamReader(in);
    }

    void noExternalEntitiesByName(InputStream in) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
        // ok: java.xxe
        factory.createXMLStreamReader(in);
    }

    void noExternalEntitiesByNameBoxed(InputStream in) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty("javax.xml.stream.isSupportingExternalEntities", Boolean.FALSE);
        // ok: java.xxe
        factory.createXMLStreamReader(in);
    }
}

// XSLT: TransformerFactory.
class TransformImports {
    void plain(InputStream in, StringWriter out) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        // ruleid: java.xxe
        transformer.transform(new StreamSource(in), new StreamResult(out));
    }

    void chained(InputStream in, StringWriter out) throws Exception {
        // ruleid: java.xxe
        TransformerFactory.newInstance().newTransformer().transform(new StreamSource(in), new StreamResult(out));
    }

    void saxFactory(InputStream in, InputStream xsl, StringWriter out) throws Exception {
        SAXTransformerFactory factory = (SAXTransformerFactory) TransformerFactory.newInstance();
        StreamSource source = new StreamSource(in);
        // ruleid: java.xxe
        factory.newTransformer(new StreamSource(xsl)).transform(source, new StreamResult(out));
    }

    void denied(InputStream in, StringWriter out) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer transformer = factory.newTransformer();
        // ok: java.xxe
        transformer.transform(new StreamSource(in), new StreamResult(out));
    }

    void chainedFactory(InputStream in, StringWriter out) throws Exception {
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        // ruleid: java.xxe
        transformer.transform(new StreamSource(in), new StreamResult(out));
    }

    void chainedFactorySourceVariable(InputStream in, StringWriter out) throws Exception {
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        StreamSource source = new StreamSource(in);
        // ruleid: java.xxe
        transformer.transform(source, new StreamResult(out));
    }

    // The stylesheet itself is parsed, whatever the input is.
    void stylesheetFromStream(InputStream xsl, Document document, StringWriter out) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer(new StreamSource(xsl));
        // todoruleid: java.xxe
        transformer.transform(new DOMSource(document), new StreamResult(out));
    }

    // Writing a DOM tree out parses no XML.
    void serialise(Document document, StringWriter out) throws Exception {
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        // ok: java.xxe
        transformer.transform(new DOMSource(document), new StreamResult(out));
    }

    // A transformer from compiled Templates is not followed.
    void templates(InputStream in, InputStream xsl, StringWriter out) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        javax.xml.transform.Templates templates = factory.newTemplates(new StreamSource(xsl));
        // todoruleid: java.xxe
        templates.newTransformer().transform(new StreamSource(in), new StreamResult(out));
    }
}

// Validation: SchemaFactory.
class SchemaImports {
    Schema plain(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    Schema denied(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        // ok: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    // External schemas (xs:import, schemaLocation) are still fetched.
    Schema dtdOnly(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        // todoruleid: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }
}

// dom4j.
class Dom4jImports {
    org.dom4j.Document plain(InputStream in) throws Exception {
        SAXReader reader = new SAXReader();
        // ruleid: java.xxe
        return reader.read(in);
    }

    org.dom4j.Document chained(InputStream in) throws Exception {
        // ruleid: java.xxe
        return new SAXReader().read(in);
    }

    org.dom4j.Document secureDefault(InputStream in) throws Exception {
        SAXReader reader = SAXReader.createDefault();
        // ok: java.xxe
        return reader.read(in);
    }

    org.dom4j.Document disallowed(InputStream in) throws Exception {
        SAXReader reader = new SAXReader();
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ok: java.xxe
        return reader.read(in);
    }

    org.dom4j.Document text(String xml) throws Exception {
        // ok: java.xxe
        return DocumentHelper.parseText(xml);
    }

    // A reader given its own XMLReader: that reader's settings are not followed.
    org.dom4j.Document ownReader(InputStream in) throws Exception {
        SAXReader reader = new SAXReader(XMLReaderFactory.createXMLReader());
        // todoruleid: java.xxe
        return reader.read(in);
    }
}

// JDOM.
class JdomImports {
    org.jdom2.Document plain(InputStream in) throws Exception {
        SAXBuilder builder = new SAXBuilder();
        // ruleid: java.xxe
        return builder.build(in);
    }

    org.jdom2.Document chained(StringReader in) throws Exception {
        // ruleid: java.xxe
        return new SAXBuilder().build(in);
    }

    org.jdom2.Document validating(InputStream in) throws Exception {
        SAXBuilder builder = new SAXBuilder(XMLReaders.DTDVALIDATING);
        // ruleid: java.xxe
        return builder.build(in);
    }

    org.jdom2.Document disallowed(InputStream in) throws Exception {
        SAXBuilder builder = new SAXBuilder();
        builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ok: java.xxe
        return builder.build(in);
    }

    org.jdom2.Document ownFactory(InputStream in, org.jdom2.input.sax.XMLReaderJDOMFactory hardened) throws Exception {
        SAXBuilder builder = new SAXBuilder(hardened);
        // ok: java.xxe
        return builder.build(in);
    }
}
