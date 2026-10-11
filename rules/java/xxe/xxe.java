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
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.sax.SAXTransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
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

    Document externalAccessDeniedInTryFinally(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        } finally {
            factory.setNamespaceAware(true);
        }
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    Document externalAccessDeniedByNameInTryFinally(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        } finally {
            factory.setNamespaceAware(true);
        }
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // Secure processing set only under a condition still counts.
    Document builtInSecureOnlyIfStrict(InputStream in, boolean strict) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newDefaultInstance();
        if (strict) {
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        }
        // todoruleid: java.xxe
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

    // A try block with a finally clause, with or without catch clauses.
    Document disallowedInTryFinally(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            factory.setFeature(DISALLOW_DOCTYPE, true);
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        } finally {
            factory.setNamespaceAware(true);
        }
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    Document disallowedInTryWithTwoCatchesAndFinally(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        } catch (RuntimeException e) {
            throw e;
        } finally {
            factory.setXIncludeAware(false);
        }
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    Document externalEntitiesOffInTryFinally(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        } finally {
            factory.setNamespaceAware(true);
        }
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // The three entity features in the other orders, in a try block with a finally clause.
    void externalEntitiesOffInOtherOrdersInTryFinally(InputStream in) throws Exception {
        DocumentBuilderFactory a = DocumentBuilderFactory.newInstance();
        DocumentBuilderFactory b = DocumentBuilderFactory.newInstance();
        DocumentBuilderFactory c = DocumentBuilderFactory.newInstance();
        DocumentBuilderFactory d = DocumentBuilderFactory.newInstance();
        DocumentBuilderFactory e = DocumentBuilderFactory.newInstance();
        try {
            a.setFeature("http://xml.org/sax/features/external-general-entities", false);
            a.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            a.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            b.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            b.setFeature("http://xml.org/sax/features/external-general-entities", false);
            b.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            c.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            c.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            c.setFeature("http://xml.org/sax/features/external-general-entities", false);
            d.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            d.setFeature("http://xml.org/sax/features/external-general-entities", false);
            d.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            e.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            e.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            e.setFeature("http://xml.org/sax/features/external-general-entities", false);
        } finally {
            in.mark(0);
        }
        // ok: java.xxe
        a.newDocumentBuilder().parse(in);
        // ok: java.xxe
        b.newDocumentBuilder().parse(in);
        // ok: java.xxe
        c.newDocumentBuilder().parse(in);
        // ok: java.xxe
        d.newDocumentBuilder().parse(in);
        // ok: java.xxe
        e.newDocumentBuilder().parse(in);
    }

    Document doctypeAllowedInTryFinally(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        } finally {
            factory.setNamespaceAware(true);
        }
        // ruleid: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // A setting made in a try block after the builder was created does not apply to it, but a
    // use inside the try block that holds a setting is taken as made after it.
    Document tooLateInTryFinally(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            // todoruleid: java.xxe
            DocumentBuilder builder = factory.newDocumentBuilder();
            factory.setFeature(DISALLOW_DOCTYPE, true);
            return builder.parse(in);
        } finally {
            factory.setNamespaceAware(true);
        }
    }

    // A setting made only under a condition inside a try block is taken as unconditional.
    Document disallowedInTryOnlyIfStrict(InputStream in, boolean strict) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            if (strict) {
                factory.setFeature(DISALLOW_DOCTYPE, true);
            }
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        }
        // todoruleid: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    Document disallowedInTryFinallyOnlyIfStrict(InputStream in, boolean strict) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            if (strict) {
                factory.setFeature(DISALLOW_DOCTYPE, true);
            }
        } finally {
            factory.setNamespaceAware(true);
        }
        // todoruleid: java.xxe
        return factory.newDocumentBuilder().parse(in);
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

    // Each of the three features must be set unconditionally.
    Document thirdFeatureOnlyIfStrict(InputStream in, boolean strict) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        if (strict) {
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        }
        // ruleid: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    Document secondFeatureOnlyIfStrict(InputStream in, boolean strict) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        if (strict) {
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        }
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        // ruleid: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    Document firstFeatureOnlyIfStrict(InputStream in, boolean strict) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        if (strict) {
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        }
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        // ruleid: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // The three features may be set in different places: one in a try block, two after it.
    Document featuresInTwoPlaces(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        }
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    Document entityFeaturesInTry(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        }
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
    }

    // The external DTD is not loaded only if strict, the entities are off either way.
    Document dtdOnlyIfStrictInTry(InputStream in, boolean strict) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        } finally {
            factory.setNamespaceAware(true);
        }
        if (strict) {
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        }
        // ruleid: java.xxe
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

// The three entity features on a field, set in a static block, a constructor or a method.
class FeaturesInStaticBlock {
    private static final DocumentBuilderFactory FACTORY = DocumentBuilderFactory.newInstance();

    static {
        try {
            FACTORY.setFeature("http://xml.org/sax/features/external-general-entities", false);
            FACTORY.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            FACTORY.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        } catch (ParserConfigurationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    Document parse(InputStream in) throws Exception {
        // ok: java.xxe
        return FACTORY.newDocumentBuilder().parse(in);
    }
}

class FeaturesInConstructor {
    private final SAXParserFactory factory = SAXParserFactory.newInstance();

    FeaturesInConstructor() throws Exception {
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    }

    void parse(InputStream in, DefaultHandler handler) throws Exception {
        // ok: java.xxe
        factory.newSAXParser().parse(in, handler);
    }
}

class FeaturesInMethod {
    private final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

    void configure() throws Exception {
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    }

    Document parse(InputStream in) throws Exception {
        // ok: java.xxe
        return factory.newDocumentBuilder().parse(in);
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
        reader.setErrorHandler(null);
        // ruleid: java.xxe
        reader.parse(new InputSource(in));
    }

    void readerFactoryInPlace(InputStream in) throws Exception {
        // ruleid: java.xxe
        XMLReaderFactory.createXMLReader().parse(new InputSource(in));
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

    void parserReaderFeatures(InputStream in) throws Exception {
        // ok: java.xxe
        XMLReader reader = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.parse(new InputSource(in));
    }

    // On the XMLReader of a SAXParser, a feature set only under a condition still counts.
    void parserReaderFeaturesOnlyIfStrict(InputStream in, boolean strict) throws Exception {
        // todoruleid: java.xxe
        XMLReader reader = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        if (strict) {
            reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        }
        reader.parse(new InputSource(in));
    }

    void readerFactoryFeaturesOnlyIfStrict(InputStream in, boolean strict) throws Exception {
        XMLReader reader = XMLReaderFactory.createXMLReader();
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        if (strict) {
            reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        }
        reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        // ruleid: java.xxe
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

    void builtInSecureInTryCatchFinally(InputStream in, DefaultHandler handler) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newDefaultNSInstance();
        try {
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        } finally {
            factory.setValidating(false);
        }
        // ok: java.xxe
        factory.newSAXParser().parse(in, handler);
    }

    void disallowedInTryFinally(InputStream in, DefaultHandler handler) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        try {
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
        } finally {
            factory.setNamespaceAware(true);
        }
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

    void noDtdInTryFinally(InputStream in) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        try {
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        } finally {
            factory.setProperty(XMLInputFactory.IS_COALESCING, true);
        }
        // ok: java.xxe
        factory.createXMLStreamReader(in);
    }

    // Each form of the two StAX properties, in a try block with a finally clause.
    void propertiesInTryFinally(InputStream in) throws Exception {
        XMLInputFactory a = XMLInputFactory.newInstance();
        XMLInputFactory b = XMLInputFactory.newInstance();
        XMLInputFactory c = XMLInputFactory.newInstance();
        XMLInputFactory d = XMLInputFactory.newInstance();
        XMLInputFactory e = XMLInputFactory.newInstance();
        XMLInputFactory f = XMLInputFactory.newInstance();
        XMLInputFactory g = XMLInputFactory.newInstance();
        try {
            a.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
            b.setProperty("javax.xml.stream.supportDTD", false);
            c.setProperty("javax.xml.stream.supportDTD", Boolean.FALSE);
            d.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            e.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
            f.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
            g.setProperty("javax.xml.stream.isSupportingExternalEntities", Boolean.FALSE);
        } finally {
            in.mark(0);
        }
        // ok: java.xxe
        a.createXMLStreamReader(in);
        // ok: java.xxe
        b.createXMLStreamReader(in);
        // ok: java.xxe
        c.createXMLStreamReader(in);
        // ok: java.xxe
        d.createXMLStreamReader(in);
        // ok: java.xxe
        e.createXMLStreamReader(in);
        // ok: java.xxe
        f.createXMLStreamReader(in);
        // ok: java.xxe
        g.createXMLStreamReader(in);
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
        // ruleid: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    Schema dtdOnlyByName(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        // ruleid: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    // External DTDs and entity references in the schema documents are still fetched.
    Schema schemaOnly(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        // ruleid: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    // A refused DOCTYPE does not stop xs:import or schemaLocation.
    Schema doctypeRefused(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ruleid: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    // Secure processing alone is not a portable restriction on a factory found by lookup.
    Schema secureProcessingOnly(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        // ruleid: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    Schema chained(InputStream xsd) throws Exception {
        // ruleid: java.xxe
        return SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI).newSchema(new StreamSource(xsd));
    }

    Schema deniedByName(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        factory.setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
        // ok: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    // The order of the two properties does not matter, nor how each is named.
    Schema deniedInOtherOrder(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        // ok: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    Schema deniedInTry(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        try {
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        } catch (org.xml.sax.SAXException e) {
            throw new IllegalStateException(e);
        }
        // ok: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    // A property set only under a condition is not hardening: each one must be set unconditionally.
    Schema schemaDeniedOnlyIfStrict(InputStream xsd, boolean strict) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        if (strict) {
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        }
        // ruleid: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    Schema dtdDeniedOnlyIfStrict(InputStream xsd, boolean strict) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
        if (strict) {
            factory.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        }
        // ruleid: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    Schema bothDeniedOnlyIfStrict(InputStream xsd, boolean strict) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        if (strict) {
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        }
        // ruleid: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    // A try block with a finally clause, with or without catch clauses.
    Schema deniedInTryFinally(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        try {
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } finally {
            factory.setErrorHandler(null);
        }
        // ok: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    Schema deniedByNameInTryCatchFinally(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        try {
            factory.setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
            factory.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        } catch (org.xml.sax.SAXException e) {
            throw new IllegalStateException(e);
        } finally {
            factory.setErrorHandler(null);
        }
        // ok: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    Schema builtInSecureInTryFinally(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newDefaultInstance();
        try {
            factory.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);
        } finally {
            factory.setErrorHandler(null);
        }
        // ok: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    // Each property may be set in its own place: one in a try block, the other after it.
    Schema deniedInTwoPlaces(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        try {
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        } catch (org.xml.sax.SAXException e) {
            throw new IllegalStateException(e);
        }
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        // ok: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }

    // The built-in JDK factory denies external access once secure processing is set explicitly.
    Schema builtInSecure(InputStream xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newDefaultInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        // ok: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }
}

// A SchemaFactory in a field, set up in a static block, a constructor or a method.
class SharedSchemaFactory {
    private static final SchemaFactory FACTORY = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);

    static {
        try {
            FACTORY.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        } catch (org.xml.sax.SAXException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    Schema load(InputStream xsd) throws Exception {
        // ruleid: java.xxe
        return FACTORY.newSchema(new StreamSource(xsd));
    }
}

class HardenedSchemaInStaticBlock {
    private static final SchemaFactory FACTORY = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);

    static {
        try {
            FACTORY.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            FACTORY.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (org.xml.sax.SAXException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    Schema load(InputStream xsd) throws Exception {
        // ok: java.xxe
        return FACTORY.newSchema(new StreamSource(xsd));
    }
}

class HardenedSchemaInConstructor {
    private final SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);

    HardenedSchemaInConstructor() throws Exception {
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    }

    Schema load(InputStream xsd) throws Exception {
        // ok: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }
}

class HardenedSchemaInMethod {
    private final SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);

    void configure() throws Exception {
        factory.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    }

    Schema load(InputStream xsd) throws Exception {
        // ok: java.xxe
        return factory.newSchema(new StreamSource(xsd));
    }
}

// Validation: a Validator from a Schema parses the document it validates.
class ValidatorImports {
    void plain(Schema schema, InputStream in) throws Exception {
        Validator validator = schema.newValidator();
        // ruleid: java.xxe
        validator.validate(new StreamSource(in));
    }

    // External schemas named by schemaLocation are still fetched.
    void dtdOnly(Schema schema, InputStream in) throws Exception {
        Validator validator = schema.newValidator();
        validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        // ruleid: java.xxe
        validator.validate(new StreamSource(in));
    }

    // External DTDs of the document are still fetched.
    void schemaOnly(Schema schema, InputStream in) throws Exception {
        Validator validator = schema.newValidator();
        validator.setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
        // ruleid: java.xxe
        validator.validate(new StreamSource(in));
    }

    void sourceVariable(Schema schema, InputStream in) throws Exception {
        Validator validator = schema.newValidator();
        StreamSource source = new StreamSource(in);
        // ruleid: java.xxe
        validator.validate(source);
    }

    void saxSource(Schema schema, InputStream in) throws Exception {
        Validator validator = schema.newValidator();
        // ruleid: java.xxe
        validator.validate(new SAXSource(new InputSource(in)), null);
    }

    void chained(Schema schema, InputStream in) throws Exception {
        // ruleid: java.xxe
        schema.newValidator().validate(new StreamSource(in));
    }

    void withResult(Schema schema, InputStream in, StringWriter out) throws Exception {
        Validator validator = schema.newValidator();
        validator.setErrorHandler(null);
        // ruleid: java.xxe
        validator.validate(new StreamSource(in), new StreamResult(out));
    }

    // A property set only under a condition is not hardening.
    void schemaDeniedOnlyIfStrict(Schema schema, InputStream in, boolean strict) throws Exception {
        Validator validator = schema.newValidator();
        validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        if (strict) {
            validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        }
        // ruleid: java.xxe
        validator.validate(new StreamSource(in));
    }

    // A setting made after the validation does not apply to it.
    void tooLate(Schema schema, InputStream in) throws Exception {
        Validator validator = schema.newValidator();
        // ruleid: java.xxe
        validator.validate(new StreamSource(in));
        validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    }

    // The Schema of a field set elsewhere: the Validator gets no property of a factory in sight.
    private Schema shared;

    void sharedSchema(InputStream in) throws Exception {
        Validator validator = shared.newValidator();
        // ruleid: java.xxe
        validator.validate(new StreamSource(in));
    }

    void denied(Schema schema, InputStream in) throws Exception {
        Validator validator = schema.newValidator();
        validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        // ok: java.xxe
        validator.validate(new StreamSource(in));
    }

    void deniedByNameInOtherOrder(Schema schema, InputStream in) throws Exception {
        Validator validator = schema.newValidator();
        validator.setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
        validator.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        // ok: java.xxe
        validator.validate(new StreamSource(in));
    }

    void deniedInTryFinally(Schema schema, InputStream in) throws Exception {
        Validator validator = schema.newValidator();
        try {
            validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            validator.setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
        } finally {
            validator.setErrorHandler(null);
        }
        // ok: java.xxe
        validator.validate(new StreamSource(in));
    }

    void deniedInTryCatchFinally(Schema schema, InputStream in) throws Exception {
        Validator validator = schema.newValidator();
        try {
            validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            validator.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        } catch (org.xml.sax.SAXNotRecognizedException e) {
            throw new IllegalStateException(e);
        } finally {
            validator.setErrorHandler(null);
        }
        // ok: java.xxe
        validator.validate(new StreamSource(in));
    }

    void deniedInTry(Schema schema, InputStream in) throws Exception {
        Validator validator = schema.newValidator();
        try {
            validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (org.xml.sax.SAXNotRecognizedException e) {
            throw new IllegalStateException(e);
        }
        // ok: java.xxe
        validator.validate(new StreamSource(in));
    }

    // A Validator gets the properties of the SchemaFactory that made its Schema: the factory is
    // checked where it makes the Schema.
    void fromHardenedFactory(InputStream xsd, InputStream in) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema(new StreamSource(xsd));
        Validator validator = schema.newValidator();
        // ok: java.xxe
        validator.validate(new StreamSource(in));
    }

    // The unhardened factory is reported where it makes the Schema; hardening it fixes both.
    void fromPlainFactory(InputStream xsd, InputStream in) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // ruleid: java.xxe
        Schema schema = factory.newSchema(new StreamSource(xsd));
        // ok: java.xxe
        schema.newValidator().validate(new StreamSource(in));
    }

    void fromHardenedFactoryChained(InputStream xsd, InputStream in) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        factory.setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
        Validator validator = factory.newSchema(new StreamSource(xsd)).newValidator();
        // ok: java.xxe
        validator.validate(new StreamSource(in));
    }

    // A DOM tree is not parsed again.
    void domTree(Schema schema, Document document) throws Exception {
        Validator validator = schema.newValidator();
        // ok: java.xxe
        validator.validate(new DOMSource(document));
    }

    // Bean Validation's Validator checks objects, not XML.
    void beanValidation(Object order) {
        jakarta.validation.Validator validator = jakarta.validation.Validation.buildDefaultValidatorFactory().getValidator();
        // ok: java.xxe
        validator.validate(order);
    }

    // A validator of another library with the same method name.
    void lookAlike(InputStream in) throws Exception {
        com.acme.imports.xml.Checker checker = new com.acme.imports.xml.Checker();
        // ok: java.xxe
        checker.validate(new StreamSource(in));
        // ok: java.xxe
        new com.acme.imports.xml.Checker().validate(new StreamSource(in));
    }

    // The StreamSource is for something else: the Validator checks a DOM tree.
    void domTreeBesideStream(Schema schema, Document document, InputStream xsl) throws Exception {
        StreamSource stylesheet = new StreamSource(xsl);
        Validator validator = schema.newValidator();
        // ok: java.xxe
        validator.validate(new DOMSource(document));
    }

    void saxSourceVariable(Schema schema, InputStream in) throws Exception {
        SAXSource source = new SAXSource(new InputSource(in));
        Validator validator = schema.newValidator();
        // ruleid: java.xxe
        validator.validate(source);
    }

    void deniedByNameInTry(Schema schema, InputStream in) throws Exception {
        Validator validator = schema.newValidator();
        try {
            validator.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
            validator.setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
        } catch (org.xml.sax.SAXNotRecognizedException e) {
            throw new IllegalStateException(e);
        }
        // ok: java.xxe
        validator.validate(new StreamSource(in));
    }

    void fromHardenedFactoryInPlace(InputStream xsd, InputStream in) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        // ok: java.xxe
        factory.newSchema(new StreamSource(xsd)).newValidator().validate(new StreamSource(in));
    }

    // Two validators: one of a hardened factory's Schema, one of a Schema handed in.
    void twoValidators(Schema other, InputStream xsd, InputStream in) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        Validator validator = factory.newSchema(new StreamSource(xsd)).newValidator();
        // ok: java.xxe
        validator.validate(new StreamSource(in));
        // ruleid: java.xxe
        other.newValidator().validate(new StreamSource(in));
    }

    // The Schema of a factory that is not created in sight (a parameter, a helper's result) is
    // checked nowhere else: the Validator is reported.
    void factoryHandedIn(SchemaFactory factory, InputStream xsd, InputStream in) throws Exception {
        Schema schema = factory.newSchema(new StreamSource(xsd));
        Validator validator = schema.newValidator();
        // ruleid: java.xxe
        validator.validate(new StreamSource(in));
    }

    void factoryFromHelper(InputStream xsd, InputStream in) throws Exception {
        SchemaFactory factory = com.acme.imports.xml.Schemas.factory();
        Schema schema = factory.newSchema(new StreamSource(xsd));
        // ruleid: java.xxe
        schema.newValidator().validate(new StreamSource(in));
    }

    void factoryHandedInInPlace(SchemaFactory factory, InputStream xsd, InputStream in) throws Exception {
        // ruleid: java.xxe
        factory.newSchema(new StreamSource(xsd)).newValidator().validate(new StreamSource(in));
    }

    void factoryHandedInValidatorVariable(SchemaFactory factory, InputStream xsd, InputStream in) throws Exception {
        Validator validator = factory.newSchema(new StreamSource(xsd)).newValidator();
        // ruleid: java.xxe
        validator.validate(new StreamSource(in));
    }

    // A factory made in place: the SchemaFactory branch reports its newSchema.
    void factoryInPlace(InputStream xsd, InputStream in) throws Exception {
        // ruleid: java.xxe
        Schema schema = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI).newSchema(new StreamSource(xsd));
        // ok: java.xxe
        schema.newValidator().validate(new StreamSource(in));
    }

    void factoryInPlaceValidatorVariable(InputStream xsd, InputStream in) throws Exception {
        // ruleid: java.xxe
        Validator validator = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI).newSchema(new StreamSource(xsd)).newValidator();
        // ok: java.xxe
        validator.validate(new StreamSource(in));
    }

    // A Validator that sets a property back to "all" on a Schema of a hardened factory is taken
    // as getting the factory's properties.
    void relaxedValidator(InputStream xsd, InputStream in) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        Schema schema = factory.newSchema(new StreamSource(xsd));
        Validator validator = schema.newValidator();
        validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
        // todoruleid: java.xxe
        validator.validate(new StreamSource(in));
    }

    // A Source handed in may be a StreamSource: it is not followed.
    void sourceHandedIn(Schema schema, javax.xml.transform.Source source) throws Exception {
        Validator validator = schema.newValidator();
        // todoruleid: java.xxe
        validator.validate(source);
    }
}

// A Schema made in the class from a hardened factory: its Validators get the factory's properties.
class SchemaFromFactoryInStaticBlock {
    private static final Schema SCHEMA;

    static {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        try {
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            SCHEMA = factory.newSchema(SchemaFromFactoryInStaticBlock.class.getResource("/order.xsd"));
        } catch (org.xml.sax.SAXException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    void check(InputStream in) throws Exception {
        // ok: java.xxe
        SCHEMA.newValidator().validate(new StreamSource(in));
    }
}

class SchemaFromFactoryInConstructor {
    private final Schema schema;

    SchemaFromFactoryInConstructor(java.net.URL xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        this.schema = factory.newSchema(xsd);
    }

    void check(InputStream in) throws Exception {
        Validator validator = schema.newValidator();
        // ok: java.xxe
        validator.validate(new StreamSource(in));
    }
}

class SchemaFromHelper {
    private static final Schema SCHEMA = load();

    private static Schema load() {
        try {
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            return factory.newSchema(SchemaFromHelper.class.getResource("/order.xsd"));
        } catch (org.xml.sax.SAXException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    // The Schema comes from a helper method: the factory behind it is not followed.
    void check(InputStream in) throws Exception {
        // todook: java.xxe
        SCHEMA.newValidator().validate(new StreamSource(in));
    }
}

// A Schema made from a factory field, in a field initialiser, a static block or a constructor.
class SchemaFromFactoryField {
    private static final SchemaFactory FACTORY = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    private static final Schema ORDER;
    private final Schema invoice;
    private final Schema receipt;
    // ruleid: java.xxe
    private final Schema payment = FACTORY.newSchema(SchemaFromFactoryField.class.getResource("/payment.xsd"));

    static {
        try {
            // ruleid: java.xxe
            ORDER = FACTORY.newSchema(SchemaFromFactoryField.class.getResource("/order.xsd"));
        } catch (org.xml.sax.SAXException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    SchemaFromFactoryField() throws org.xml.sax.SAXException {
        // ruleid: java.xxe
        invoice = FACTORY.newSchema(SchemaFromFactoryField.class.getResource("/invoice.xsd"));
        // ruleid: java.xxe
        this.receipt = FACTORY.newSchema(SchemaFromFactoryField.class.getResource("/receipt.xsd"));
    }

    void check(InputStream in) throws Exception {
        // ok: java.xxe
        ORDER.newValidator().validate(new StreamSource(in));
        // ok: java.xxe
        invoice.newValidator().validate(new StreamSource(in));
        // ok: java.xxe
        receipt.newValidator().validate(new StreamSource(in));
        // ok: java.xxe
        payment.newValidator().validate(new StreamSource(in));
    }
}

// The Schema made in the constructor from a factory handed in is checked nowhere else.
class SchemaFromFactoryHandedIn {
    private final Schema schema;

    SchemaFromFactoryHandedIn(SchemaFactory factory, java.net.URL xsd) throws Exception {
        this.schema = factory.newSchema(xsd);
    }

    void check(InputStream in) throws Exception {
        // ruleid: java.xxe
        schema.newValidator().validate(new StreamSource(in));
    }
}

// A parameter named like a field made from a hardened factory is not that field.
class ParameterNamedLikeField {
    private final Schema schema;

    ParameterNamedLikeField(java.net.URL xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        this.schema = factory.newSchema(xsd);
    }

    void check(Schema schema, InputStream in) throws Exception {
        // ruleid: java.xxe
        schema.newValidator().validate(new StreamSource(in));
    }
}

// A Schema assigned in another method, or named with `this.` only where it is used, is not
// followed back to its factory.
class SchemaFromFactoryInInit {
    private Schema schema;
    private final Schema other;

    SchemaFromFactoryInInit(java.net.URL xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        other = factory.newSchema(xsd);
    }

    void init(java.net.URL xsd) throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        schema = factory.newSchema(xsd);
    }

    void check(InputStream in) throws Exception {
        // todook: java.xxe
        schema.newValidator().validate(new StreamSource(in));
    }

    void checkOther(InputStream in) throws Exception {
        // todook: java.xxe
        this.other.newValidator().validate(new StreamSource(in));
    }

    void checkOtherByName(InputStream in) throws Exception {
        // ok: java.xxe
        other.newValidator().validate(new StreamSource(in));
    }
}

// A Validator in a field, hardened in a static block, the constructor or a method.
class HardenedValidatorInStaticBlock {
    private static final Schema SCHEMA = com.acme.imports.xml.Schemas.order();
    private static final Validator VALIDATOR = SCHEMA.newValidator();
    private static final Validator BY_NAME = SCHEMA.newValidator();

    static {
        try {
            VALIDATOR.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            VALIDATOR.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            BY_NAME.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
            BY_NAME.setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
        } catch (org.xml.sax.SAXException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    synchronized void check(InputStream in) throws Exception {
        // ok: java.xxe
        VALIDATOR.validate(new StreamSource(in));
        // ok: java.xxe
        BY_NAME.validate(new StreamSource(in));
    }
}

class HardenedValidatorInMethod {
    private static final Schema SCHEMA = com.acme.imports.xml.Schemas.order();
    private final Validator validator = SCHEMA.newValidator();
    private final Validator byName = SCHEMA.newValidator();

    void configure() throws Exception {
        validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        byName.setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
        byName.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
    }

    void check(InputStream in) throws Exception {
        // ok: java.xxe
        validator.validate(new StreamSource(in));
        // ok: java.xxe
        byName.validate(new StreamSource(in));
    }
}

class HardenedValidatorField {
    private static final Schema SCHEMA = com.acme.imports.xml.Schemas.order();
    private final Validator hardened = SCHEMA.newValidator();
    private final Validator byName = SCHEMA.newValidator();
    private final Validator validator;

    HardenedValidatorField(Schema schema) throws Exception {
        hardened.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        hardened.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        byName.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        byName.setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
        validator = schema.newValidator();
    }

    void check(InputStream in) throws Exception {
        // ok: java.xxe
        hardened.validate(new StreamSource(in));
        // ok: java.xxe
        byName.validate(new StreamSource(in));
    }

    // A Validator assigned in the constructor is not followed.
    void checkOther(InputStream in) throws Exception {
        // todoruleid: java.xxe
        validator.validate(new StreamSource(in));
    }
}

class PlainValidatorField {
    private static final Schema SCHEMA = com.acme.imports.xml.Schemas.order();
    private final Validator validator = SCHEMA.newValidator();

    void check(InputStream in) throws Exception {
        // ruleid: java.xxe
        validator.validate(new StreamSource(in));
    }
}

// dom4j.
class Dom4jImports {
    org.dom4j.Document plain(InputStream in) throws Exception {
        SAXReader reader = new SAXReader();
        reader.setEncoding("UTF-8");
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
        builder.setExpandEntities(false);
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
