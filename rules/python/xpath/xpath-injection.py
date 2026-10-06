import json
import re
import xml.etree.ElementTree as ET
from typing import Annotated

import defusedxml.ElementTree
from bs4 import BeautifulSoup
from django.http import HttpResponse, JsonResponse
from django.views import View
from fastapi import Depends, FastAPI, Path, Query, Request
from flask import Flask, request
from lxml import etree, html, objectify
from pydantic import BaseModel

app = Flask(__name__)
api = FastAPI()

catalog = etree.parse("catalog.xml")
DIRECTORY_TREE = ET.parse("directory.xml")
staff_root = ET.parse("staff.xml").getroot()

FIELDS = {
    # Fields a client may ask for; the request only picks one.
    "title": "//book/title/text()",
    "author": "//book/author/text()",  # the default
}
PATHS = {"users": ("users", "user"), "groups": ["groups"]}
COUNT_ALL = "count(//book)"
# A nested table is not recognised as an allow-list.
NESTED_FIELDS = {"book": {"title": "//book/title"}}
# Changed later by a view, so not an allow-list.
SAVED_QUERIES = {"recent": "//book[last()]"}


# Flask with lxml: query strings, form fields, JSON bodies, headers, cookies, URL variables.
@app.route("/books")
def books():
    author = request.args.get("author", "")
    # ruleid: python.xpath-injection
    titles = catalog.xpath("//book[author='" + author + "']/title/text()")
    root = catalog.getroot()
    # ruleid: python.xpath-injection
    found = root.xpath(f"//book[@id='{request.args['id']}']")
    return str((titles, found))


@app.route("/books/<isbn>")
def book(isbn):
    doc = etree.fromstring(open("catalog.xml", "rb").read())
    # ruleid: python.xpath-injection
    return str(doc.xpath("//book[@isbn='%s']" % isbn))


@app.post("/login")
def login():
    body = request.get_json()
    users = etree.parse("users.xml")
    # ruleid: python.xpath-injection
    match = users.xpath("//user[name/text()='{}' and password/text()='{}']".format(body["user"], body["password"]))
    # ruleid: python.xpath-injection
    check = etree.XPath("//user[name='" + request.form["name"] + "']")
    # ruleid: python.xpath-injection
    finder = etree.ETXPath("//{urn:users}user[@role='" + request.headers["X-Role"] + "']")
    return str((match, check, finder))


@app.route("/report")
def report():
    page = html.fromstring(open("report.html").read())
    # ruleid: python.xpath-injection
    cells = page.xpath(request.cookies["column"])
    evaluator = etree.XPathEvaluator(catalog)
    # ruleid: python.xpath-injection
    rows = evaluator(request.values["q"])
    # ruleid: python.xpath-injection
    more = etree.XPathDocumentEvaluator(catalog)(request.values["q2"])
    # ruleid: python.xpath-injection
    objs = objectify.parse("data.xml").getroot().xpath(request.args["path"])
    return str((cells, rows, more, objs))


# Flask with xml.etree.ElementTree: request data in a find()/findall() path.
@app.route("/staff")
def staff():
    dept = request.args["dept"]
    # ruleid: python.xpath-injection
    people = staff_root.findall(".//person[@dept='" + dept + "']")
    tree = ET.parse("staff.xml")
    # ruleid: python.xpath-injection
    first = tree.find(f".//person[name='{request.args['name']}']")
    # ruleid: python.xpath-injection
    phone = tree.findtext(".//person[@id='%s']/phone" % request.args["id"], default="")
    root = ET.fromstring(request.data)
    # ruleid: python.xpath-injection
    items = list(root.iterfind(request.args["select"]))
    safe_root = defusedxml.ElementTree.fromstring(request.data)
    # ruleid: python.xpath-injection
    names = safe_root.findall(match=".//item[@type='" + request.args["type"] + "']")
    teams = tree.find("teams")
    # ruleid: python.xpath-injection
    team = teams.find("team[@name='" + request.args["team"] + "']")
    return str((people, first, phone, items, names, team))


# Flask: XPath variables, constants, conversions, allow-lists.
@app.route("/books-safe")
def books_safe():
    author = request.args.get("author", "")
    # ok: python.xpath-injection
    a = catalog.xpath("//book[author=$author]/title/text()", author=author)
    # ok: python.xpath-injection
    b = etree.XPath("//book[@id=$id]")(catalog, id=request.args["id"])
    # ok: python.xpath-injection
    c = catalog.xpath(COUNT_ALL)
    # ok: python.xpath-injection
    d = catalog.xpath("//book[%d]" % int(request.args["n"]))
    # ok: python.xpath-injection
    e = staff_root.findall(".//person")
    # ok: python.xpath-injection
    f = staff_root.findtext("name", default=request.args.get("fallback", ""))
    # ok: python.xpath-injection
    g = etree.XPathEvaluator(catalog)("//book[@lang=$lang]", lang=request.args["lang"])
    return str((a, b, c, d, e, f, g))


@app.route("/field/<name>")
def field(name):
    # ok: python.xpath-injection
    a = catalog.xpath(FIELDS.get(name, FIELDS["author"]))
    # ok: python.xpath-injection
    b = staff_root.findall("/".join(PATHS[name]))
    # ok: python.xpath-injection
    c = catalog.xpath(FIELDS[name] if name in FIELDS else COUNT_ALL)
    # ruleid: python.xpath-injection
    d = catalog.xpath(FIELDS.get(name, request.args["expr"]))
    # ruleid: python.xpath-injection
    e = catalog.xpath(SAVED_QUERIES[name])
    # todook: python.xpath-injection
    f = catalog.xpath(NESTED_FIELDS["book"][name])
    DEFAULT_FIELD = request.args["field"]
    # ruleid: python.xpath-injection
    g = catalog.xpath(FIELDS.get(name, DEFAULT_FIELD))
    return str((a, b, c, d, e, f, g))


@app.post("/queries")
def save_query():
    SAVED_QUERIES[request.form["name"]] = request.form["xpath"]
    return "ok"


# Look-alikes: str.find, re.findall, BeautifulSoup's find(), a document store's find().
@app.route("/lookalikes")
def lookalikes():
    q = request.args["q"]
    # ok: python.xpath-injection
    a = "catalog of books".find(q)
    # ok: python.xpath-injection
    b = re.findall(r"\w+", q)
    soup = BeautifulSoup(open("page.html").read(), "html.parser")
    # ok: python.xpath-injection
    c = soup.find(q)
    # ok: python.xpath-injection
    d = list(store.books.find({"title": q}))
    return str((a, b, c, d))


store = None


# A membership check against an allow-list is not recognised.
@app.route("/sort")
def sort():
    key = request.args["key"]
    if key not in ("title", "author"):
        return "bad", 400
    # todook: python.xpath-injection
    return str(catalog.xpath("//book/" + key + "/text()"))


# A slice of request data: OpenGrep does not carry taint through a slice, so the rule takes a
# slice of a request value (in place or through a variable) or of a view parameter as request
# data itself. A slice of a value built from request data is missed.
@app.route("/short")
def short():
    q = request.args["q"]
    # ruleid: python.xpath-injection
    catalog.xpath(q[:50])
    # todoruleid: python.xpath-injection
    catalog.xpath(("//item[@id='" + request.args["q"])[:50])
    # ruleid: python.xpath-injection
    return str(catalog.xpath(request.args["q"][:50]))


# xpath() in a module that imports lxml: any receiver (a tree from a helper, a parameter, an
# attribute, an element of a result list); getroot() chained on an assigned tree.
def load_catalog():
    return etree.parse("catalog.xml")


class Library:
    def __init__(self):
        self.doc = etree.parse("library.xml")


library = Library()


def books_by_shelf(root):
    # ruleid: python.xpath-injection
    return root.xpath("//book[@shelf='" + request.args["shelf"] + "']")


@app.route("/helper-tree")
def helper_tree():
    loaded = load_catalog()
    # ruleid: python.xpath-injection
    a = loaded.xpath("//book[@id='" + request.args["id"] + "']")
    # ruleid: python.xpath-injection
    b = library.doc.xpath("//book[title='%s']" % request.args["title"])
    # ruleid: python.xpath-injection
    c = catalog.xpath("//shelf")[0].xpath(request.args["rel"])
    shelves = catalog.xpath("//shelf")
    # ruleid: python.xpath-injection
    d = shelves[0].xpath("book[@lang='" + request.args["lang"] + "']")
    # ruleid: python.xpath-injection
    e = catalog.getroot().xpath(request.args["q"])
    for row in catalog.xpath("//book"):
        # ruleid: python.xpath-injection
        f = row.xpath("author[@role='" + request.args["role"] + "']")
    return str((a, b, c, d, e, f))


@app.route("/staff-root")
def staff_tree_root():
    tree = ET.parse("staff.xml")
    # ruleid: python.xpath-injection
    a = tree.getroot().findall(".//person[@dept='" + request.args["dept"] + "']")
    # ruleid: python.xpath-injection
    b = list(tree.getroot().iterfind(request.args["select"]))
    # ruleid: python.xpath-injection
    c = catalog.getroot().findtext("book[@id='%s']/title" % request.args["id"])
    return str((a, b, c))


# find(), findall(), findtext() and iterfind() stay bound to a tree the rule can see: an element
# reached by iteration or taken from a result list, a tree on an attribute or received as a
# parameter, and a tree returned by a helper are missed.
def people_in(root):
    # todoruleid: python.xpath-injection
    return root.findall(".//person[@dept='" + request.args["dept"] + "']")


class Directory:
    def __init__(self):
        self.root = ET.parse("staff.xml").getroot()


directory = Directory()


@app.route("/staff-helpers")
def staff_helpers():
    for person in staff_root.iter("person"):
        # todoruleid: python.xpath-injection
        a = person.find("phone[@type='" + request.args["type"] + "']")
    # todoruleid: python.xpath-injection
    b = staff_root.findall("team")[0].find("member[@name='" + request.args["name"] + "']")
    # todoruleid: python.xpath-injection
    c = directory.root.findall(".//person[@id='" + request.args["id"] + "']")
    loaded = reload_staff()
    # todoruleid: python.xpath-injection
    d = loaded.find(".//person[@id='" + request.args["id"] + "']")
    return str((a, b, c, d))


def reload_staff():
    return ET.parse("staff.xml")


# Flask typed converter: the rule cannot see that <int:n> is an int.
@app.route("/nth/<int:n>")
def nth(n):
    # todook: python.xpath-injection
    return str(catalog.xpath("//book[%s]" % n))


# A Flask view parameter annotated int is not a source, although Flask passes a str for a
# <name> rule without a converter.
@app.route("/legacy/<legacy_path>")
def legacy(legacy_path: int):
    # todoruleid: python.xpath-injection
    return str(catalog.xpath(legacy_path))


# Django: GET, POST, body, URL arguments, class-based views.
def django_books(request):
    # ruleid: python.xpath-injection
    titles = catalog.xpath("//book[author='" + request.GET["author"] + "']/title/text()")
    return JsonResponse({"titles": [str(t) for t in titles]})


def django_staff(request, dept):
    payload = json.loads(request.body)
    # ruleid: python.xpath-injection
    phone = DIRECTORY_TREE.getroot().findtext(".//person[@id='%s']/phone" % payload["id"])
    # ruleid: python.xpath-injection
    people = staff_root.findall(".//person[@dept='" + dept + "']")
    # ruleid: python.xpath-injection
    roles = catalog.xpath("//role[@name='%s']" % payload["role"])
    return HttpResponse(str((people, roles, phone)))


class SearchView(View):
    def post(self, request):
        # ruleid: python.xpath-injection
        hits = catalog.xpath(self.request.POST["xpath"])
        # ok: python.xpath-injection
        safe = catalog.xpath("//book[title=$t]", t=self.request.POST["title"])
        return HttpResponse(str((hits, safe)))


# path("nth/<int:pk>/", views.django_nth): the converter is in urls.py.
def django_nth(request, pk):
    # todook: python.xpath-injection
    return HttpResponse(str(catalog.xpath("//book[%s]" % pk)))


# A default value: Django passes the URL value when the pattern captures one.
def django_default(request, path="//book"):
    # todook: python.xpath-injection
    return HttpResponse(str(catalog.xpath(path)))


# Helpers whose first parameter is named request look like views: other parameters count as URL
# arguments, and an outgoing request (an HTTP client's) has its headers taken as request data.
def select_for(request, selector):
    # todook: python.xpath-injection
    return catalog.xpath(selector)


def select_header(request):
    # todook: python.xpath-injection
    return catalog.xpath(request.headers["X-Select"])


# FastAPI: query and path parameters, bodies, the Request object.
class Search(BaseModel):
    title: str
    lang: str = "en"


@api.post("/search/{genre}")
async def search(genre: str, search: Search, request: Request, author: str = ""):
    # ruleid: python.xpath-injection
    a = catalog.xpath("//book[@genre='" + genre + "']")
    # ruleid: python.xpath-injection
    b = catalog.xpath(f"//book[title='{search.title}']")
    # ruleid: python.xpath-injection
    c = staff_root.findall(".//person[name='" + author + "']")
    # ruleid: python.xpath-injection
    d = catalog.xpath(request.query_params["q"])
    # ok: python.xpath-injection
    e = catalog.xpath("//book[@lang=$lang and @genre=$genre]", lang=search.lang, genre=genre)
    return {"n": len(a) + len(b) + len(c) + len(d) + len(e)}


class Settings(BaseModel):
    default_xpath: str = "//book"


def get_settings():
    return Settings()


SettingsDep = Annotated[Settings, Depends(get_settings)]


@api.get("/top/{n}")
async def top(
    n: Annotated[int, Path()],
    settings: SettingsDep,
    other: Annotated[Settings, Depends(get_settings)],
    legacy: Settings = Depends(get_settings),
    lang: Annotated[str, Query()] = "",
):
    # ok: python.xpath-injection
    a = catalog.xpath(settings.default_xpath)
    # ok: python.xpath-injection
    b = catalog.xpath(other.default_xpath + legacy.default_xpath)
    # ok: python.xpath-injection
    c = catalog.xpath("//book[position() <= " + str(n) + "]")
    # ruleid: python.xpath-injection
    d = catalog.xpath("//book[@lang='" + lang + "']")
    return {"n": len(a) + len(b) + len(c) + len(d)}
