import io
import xml.dom.minidom
import xml.etree.ElementTree as ET
import xml.sax
from xml.dom import pulldom
from xml.sax import handler, make_parser
from xml.sax.handler import feature_external_ges, feature_external_pes, feature_namespaces

import defusedxml.ElementTree
import defusedxml.sax
from flask import Flask, request
from lxml import etree, html, objectify

app = Flask(__name__)

RESOLVE_EXTERNAL = True


# lxml: resolve_entities=True loads external entities (local files, and URLs when network
# access is on); no_network=False lets the parser fetch related documents over the network.
@app.post("/lxml")
def lxml_views():
    # ruleid: python.xxe
    parser = etree.XMLParser(resolve_entities=True)
    doc = etree.fromstring(request.data, parser)
    # ruleid: python.xxe
    remote = etree.XMLParser(no_network=False)
    # ruleid: python.xxe
    validating = etree.XMLParser(resolve_entities=False, dtd_validation=True, no_network=False)
    # ruleid: python.xxe
    both = etree.XMLParser(load_dtd=True, no_network=False, resolve_entities=True)
    # ruleid: python.xxe
    compat = etree.ETCompatXMLParser(resolve_entities=True, remove_blank_text=True)
    # ruleid: python.xxe
    builder = etree.XMLTreeBuilder(no_network=False)
    # ruleid: python.xxe
    xhtml = html.XHTMLParser(resolve_entities=True)
    # ruleid: python.xxe
    pull = etree.XMLPullParser(events=("end",), resolve_entities=True)
    # ruleid: python.xxe
    for event, element in etree.iterparse(io.BytesIO(request.data), resolve_entities=True):
        pass
    # ruleid: python.xxe
    for event, element in etree.iterparse(io.BytesIO(request.data), events=("start",), no_network=False):
        pass
    # ruleid: python.xxe
    obj_parser = objectify.makeparser(resolve_entities=True)
    # ruleid: python.xxe
    etree.set_default_parser(etree.XMLParser(resolve_entities=True, no_network=True))
    # ruleid: python.xxe
    tree = etree.parse("feed.xml", etree.XMLParser(resolve_entities=RESOLVE_EXTERNAL))
    return str((doc, remote, validating, both, compat, builder, xhtml, pull, obj_parser, tree))


# lxml: the defaults (resolve_entities='internal', no_network=True since lxml 5.0) and the
# explicit safe settings.
@app.post("/lxml-safe")
def lxml_safe():
    # ok: python.xxe
    a = etree.fromstring(request.data)
    # ok: python.xxe
    b = etree.XMLParser()
    # ok: python.xxe
    c = etree.XMLParser(resolve_entities=False, no_network=True)
    # Entities off and no DTD loaded: nothing external to fetch.
    # ok: python.xxe
    c2 = etree.XMLParser(no_network=False, resolve_entities=False)
    # ok: python.xxe
    d = etree.XMLParser(resolve_entities="internal", remove_comments=True)
    # ok: python.xxe
    e = etree.ETCompatXMLParser(no_network=True)
    # ok: python.xxe
    f = objectify.makeparser(remove_blank_text=True)
    # ok: python.xxe
    for event, element in etree.iterparse(io.BytesIO(request.data), resolve_entities=False):
        pass
    # ok: python.xxe
    g = etree.HTMLParser(remove_comments=True)
    # ok: python.xxe
    h = html.XHTMLParser(resolve_entities=False)
    return str((a, b, c, c2, d, e, f, g, h))


# xml.sax, pulldom and minidom: since Python 3.7.1 the SAX parser does not include external
# general entities unless feature_external_ges is turned on.
@app.post("/sax")
def sax_views():
    parser = make_parser()
    # ruleid: python.xxe
    parser.setFeature(feature_external_ges, True)
    xml.sax.parseString(request.data, handler.ContentHandler())

    events_parser = xml.sax.make_parser()
    # ruleid: python.xxe
    events_parser.setFeature(handler.feature_external_ges, 1)
    events = pulldom.parseString(request.data.decode(), parser=events_parser)

    keyword_parser = make_parser()
    # ruleid: python.xxe
    keyword_parser.setFeature(feature_external_ges, state=True)

    dom_parser = make_parser()
    # ruleid: python.xxe
    dom_parser.setFeature("http://xml.org/sax/features/external-general-entities", True)
    dom = xml.dom.minidom.parseString(request.data, parser=dom_parser)
    return str((events, dom))


@app.post("/sax-safe")
def sax_safe():
    parser = make_parser()
    # ok: python.xxe
    parser.setFeature(feature_external_ges, False)
    # ok: python.xxe
    parser.setFeature(feature_namespaces, True)
    # ok: python.xxe
    parser.setFeature(name=feature_external_ges, state=False)
    # The expat-based parser refuses external parameter entities (SAXNotSupportedException).
    # ok: python.xxe
    parser.setFeature(feature_external_pes, True)
    # ok: python.xxe
    events = pulldom.parseString(request.data.decode())
    # ok: python.xxe
    dom = xml.dom.minidom.parseString(request.data)
    # ok: python.xxe
    root = ET.fromstring(request.data)
    return str((events, dom, root))


# defusedxml: its parsers forbid external entities whatever the SAX features say.
@app.post("/defused")
def defused():
    # ok: python.xxe
    root = defusedxml.ElementTree.fromstring(request.data)
    parser = defusedxml.sax.make_parser()
    # ok: python.xxe
    parser.setFeature(feature_external_ges, True)
    return str(root)


# Look-alikes: an option of the same name on another library's object.
@app.post("/lookalikes")
def lookalikes():
    # ok: python.xxe
    cfg = ImporterConfig(resolve_entities=True, no_network=False)
    # ok: python.xxe
    cfg.setFeature("external-general-entities", True)
    return str(cfg)


class ImporterConfig:
    def __init__(self, **options):
        self.options = options

    def setFeature(self, name, value):
        self.options[name] = value


# Options passed as a dict are not seen.
@app.post("/options")
def options():
    opts = {"resolve_entities": True}
    # todoruleid: python.xxe
    parser = etree.XMLParser(**opts)
    return str(parser)


# Loading the external DTD a document names: the lxml FAQ advises against it for untrusted
# input, but DTD validation of trusted documents is its documented use, so it is not reported.
@app.post("/dtd")
def dtd():
    # todoruleid: python.xxe
    parser = etree.XMLParser(load_dtd=True)
    # todoruleid: python.xxe
    validating = etree.XMLParser(dtd_validation=True)
    # todoruleid: python.xxe
    defaults = etree.XMLParser(attribute_defaults=True)
    return str((parser, validating, defaults))
