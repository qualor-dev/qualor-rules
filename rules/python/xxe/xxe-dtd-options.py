import io

from flask import Flask, request
from lxml import etree, html, objectify

app = Flask(__name__)

HUGE_DOCUMENTS = True


# DTD loading: load_dtd=True reads the DTD a document names, and dtd_validation=True and
# attribute_defaults=True load it too. huge_tree=True lifts libxml2's security limits on depth,
# text size and entity expansion.
@app.post("/import")
def import_feed():
    # ruleid: python.xxe-dtd-options
    loading = etree.XMLParser(load_dtd=True)
    # ruleid: python.xxe-dtd-options
    validating = etree.XMLParser(dtd_validation=True)
    # ruleid: python.xxe-dtd-options
    defaults = etree.XMLParser(attribute_defaults=True, remove_blank_text=True)
    # ruleid: python.xxe-dtd-options
    huge = etree.XMLParser(huge_tree=True)
    doc = etree.fromstring(request.data, huge)
    # Entities off and the network blocked: the DTD is still read from the local file system.
    # ruleid: python.xxe-dtd-options
    strict = etree.XMLParser(dtd_validation=True, resolve_entities=False, no_network=True)
    # ruleid: python.xxe-dtd-options
    compat = etree.ETCompatXMLParser(attribute_defaults=True)
    # ruleid: python.xxe-dtd-options
    builder = etree.XMLTreeBuilder(load_dtd=True)
    # ruleid: python.xxe-dtd-options
    xhtml = html.XHTMLParser(dtd_validation=True)
    # ruleid: python.xxe-dtd-options
    pull = etree.XMLPullParser(events=("end",), load_dtd=True)
    # ruleid: python.xxe-dtd-options
    for event, element in etree.iterparse(io.BytesIO(request.data), events=("end",), huge_tree=True):
        pass
    # ruleid: python.xxe-dtd-options
    obj_parser = objectify.makeparser(huge_tree=True)
    # ruleid: python.xxe-dtd-options
    constant = etree.XMLParser(huge_tree=HUGE_DOCUMENTS)
    # Network on with entities off: python.xxe does not report it, as nothing external is
    # resolved, but the limits are still lifted.
    # ruleid: python.xxe-dtd-options
    remote = etree.XMLParser(no_network=False, resolve_entities=False, huge_tree=True)
    return str((loading, validating, defaults, doc, strict, compat, builder, xhtml, pull, obj_parser, constant, remote))


# The defaults (no DTD loaded, limits on) and the options turned off.
@app.post("/import-safe")
def import_safe():
    # ok: python.xxe-dtd-options
    a = etree.XMLParser()
    # ok: python.xxe-dtd-options
    b = etree.XMLParser(load_dtd=False, huge_tree=False)
    # ok: python.xxe-dtd-options
    c = etree.XMLParser(resolve_entities=False, no_network=True, remove_comments=True)
    # ok: python.xxe-dtd-options
    d = objectify.makeparser(remove_blank_text=True)
    # ok: python.xxe-dtd-options
    for event, element in etree.iterparse(io.BytesIO(request.data), events=("start",)):
        pass
    # ok: python.xxe-dtd-options
    e = etree.fromstring(request.data)
    # The HTML parser reads no DTD and expands no entities.
    # ok: python.xxe-dtd-options
    f = etree.HTMLParser(huge_tree=True)
    return str((a, b, c, d, e, f))


# Already reported by python.xxe (entities resolved, or the network on with a DTD loaded): one
# finding per parser is enough.
@app.post("/import-xxe")
def import_xxe():
    # ok: python.xxe-dtd-options
    a = etree.XMLParser(load_dtd=True, resolve_entities=True)
    # ok: python.xxe-dtd-options
    b = etree.XMLParser(dtd_validation=True, no_network=False)
    # ok: python.xxe-dtd-options
    c = etree.XMLParser(huge_tree=True, no_network=False)
    return str((a, b, c))


# Look-alikes: options of the same names on another library's object.
@app.post("/lookalikes")
def lookalikes():
    # ok: python.xxe-dtd-options
    cfg = ImporterConfig(load_dtd=True, huge_tree=True)
    # ok: python.xxe-dtd-options
    cfg.configure(dtd_validation=True, attribute_defaults=True)
    return str(cfg)


class ImporterConfig:
    def __init__(self, **options):
        self.options = options

    def configure(self, **options):
        self.options.update(options)


# Options passed as a dict are not seen.
@app.post("/options")
def options():
    opts = {"load_dtd": True}
    # todoruleid: python.xxe-dtd-options
    parser = etree.XMLParser(**opts)
    return str(parser)
