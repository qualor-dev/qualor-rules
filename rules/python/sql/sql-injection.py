import json
import urllib.request
import logging
import sqlite3
from typing import Annotated

import graphene
import psycopg
import psycopg2
from django.db import connection, connections, models
from django.db.models.expressions import RawSQL
from django.http import HttpResponse
from django.views import View
from fastapi import Depends, FastAPI, Path, Query
from flask import Blueprint, Flask, request
from flask_sqlalchemy import SQLAlchemy
from psycopg2 import sql
from sqlalchemy import delete, insert, select, text, update

app = Flask(__name__)
bp = Blueprint("admin", __name__)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)


class Query(graphene.ObjectType):
    name = graphene.String()


schema = graphene.Schema(query=Query)


def get_db():
    return sqlite3.connect("shop.db")


def login_required(view):
    return view


@app.route("/orders")
def orders():
    con = sqlite3.connect("shop.db")
    cur = con.cursor()
    customer = request.args.get("customer")
    # ruleid: python.sql-injection
    cur.execute("SELECT * FROM orders WHERE customer = '%s'" % customer)
    # ruleid: python.sql-injection
    cur.execute(f"SELECT * FROM orders WHERE id = {request.args['id']}")
    query = "DELETE FROM orders WHERE note = '" + request.form["note"] + "'"
    # ruleid: python.sql-injection
    cur.execute(query)
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM items WHERE name = '{}'".format(request.values.get("name")))
    # ruleid: python.sql-injection
    cur.executemany("INSERT INTO log VALUES ('" + request.headers.get("User-Agent") + "', ?)", [(1,)])
    # ok: python.sql-injection
    cur.execute("SELECT * FROM orders WHERE customer = ?", (customer,))
    # ok: python.sql-injection
    cur.execute("SELECT * FROM orders WHERE id = :id", {"id": request.args["id"]})
    # ok: python.sql-injection
    cur.execute("SELECT count(*) FROM orders")
    column = "price" if request.args.get("sort") == "price" else "name"
    # ok: python.sql-injection
    cur.execute("SELECT * FROM items ORDER BY " + column)
    # ok: python.sql-injection
    cur.execute("SELECT * FROM items WHERE id = %d" % int(request.args["id"]))
    return "ok"


# Flask "Variable Rules": the URL parts named in the route reach the view as arguments.
@app.route("/users/<name>")
def user(name):
    con = get_db()
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM users WHERE name = '" + name + "'")
    # ok: python.sql-injection
    con.execute("SELECT * FROM users WHERE name = ?", (name,))
    return "ok"


@app.get("/search/<path:term>")
@login_required
def search(term):
    cur = get_db().cursor()
    statement = "SELECT * FROM pages WHERE body LIKE '%" + term + "%'"
    # ruleid: python.sql-injection
    cur.execute(statement)
    return "ok"


@app.post("/notes/<note_id>")
def add_note(note_id):
    cur = get_db().cursor()
    # ruleid: python.sql-injection
    cur.execute("UPDATE notes SET body = ? WHERE id = " + note_id, (request.get_data(as_text=True),))
    # ruleid: python.sql-injection
    cur.execute("UPDATE notes SET body = '%s' WHERE id = 1" % request.get_data(as_text=True))
    return "ok"


@app.route("/orders/<int:order_id>")
def order(order_id):
    cur = get_db().cursor()
    # todook: python.sql-injection
    cur.execute("SELECT * FROM orders WHERE id = %d" % order_id)
    return "ok"


@app.route("/pages/<slug>", methods=["POST"])
def upload(slug):
    con = get_db()
    report = request.files["report"]
    # ruleid: python.sql-injection
    con.execute(f"INSERT INTO uploads (name) VALUES ('{report.filename}')")
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM pages WHERE slug = '" + request.view_args["slug"] + "'")
    # ruleid: python.sql-injection
    con.execute("INSERT INTO visits (path) VALUES ('%s')" % request.full_path)
    # ruleid: python.sql-injection
    con.execute("INSERT INTO visits (path) VALUES ('" + request.path + "')")
    # ruleid: python.sql-injection
    con.execute(f"INSERT INTO visits (url) VALUES ('{request.url}')")
    # ruleid: python.sql-injection
    con.execute("INSERT INTO visits (query) VALUES ('%s')" % request.query_string.decode())
    # ok: python.sql-injection
    con.execute("INSERT INTO visits (path, query) VALUES (?, ?)", (request.path, request.query_string))
    return "ok"


# psycopg2 "SQL string composition": identifiers and values through sql.Identifier / sql.Literal.
@app.route("/tables")
def tables():
    conn = psycopg2.connect("dbname=shop")
    cur = conn.cursor()
    # ok: python.sql-injection
    cur.execute(sql.SQL("SELECT * FROM {}").format(sql.Identifier(request.args["t"])))
    # ok: python.sql-injection
    cur.execute(sql.SQL("SELECT * FROM orders WHERE note = {}").format(sql.Literal(request.args["note"])))
    # ok: python.sql-injection
    cur.execute("SELECT * FROM orders WHERE note = %s", (request.args["note"],))
    # ruleid: python.sql-injection
    cur.execute(sql.SQL("SELECT * FROM orders WHERE note = '" + request.args["note"] + "'"))
    with conn.cursor() as curs:
        # ruleid: python.sql-injection
        curs.execute("SELECT * FROM orders WHERE note = '%s'" % request.args["note"])
    with psycopg.connect("dbname=shop") as aconn:
        # ruleid: python.sql-injection
        aconn.execute(f"SELECT * FROM orders WHERE note = '{request.args['note']}'")
        # ok: python.sql-injection
        aconn.execute("SELECT * FROM orders WHERE note = %s", (request.args["note"],))
    return "ok"


# SQLAlchemy 2.x (and Flask-SQLAlchemy): statements built with select/insert/update/delete bind
# their values; only textual SQL (text(), exec_driver_sql()) takes the query as a string.
@app.route("/members")
def members():
    name = request.args["n"]
    # ok: python.sql-injection
    db.session.execute(select(User).where(User.name == request.args["n"]))
    # ok: python.sql-injection
    db.session.execute(db.select(User).filter_by(name=name))
    # ok: python.sql-injection
    db.session.execute(update(User).where(User.id == request.args["id"]).values(name=name))
    # ok: python.sql-injection
    db.session.execute(insert(User).values(name=name))
    # ok: python.sql-injection
    db.session.execute(delete(User).where(User.name == name))
    # ok: python.sql-injection
    db.session.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})
    # ok: python.sql-injection
    db.session.execute(text("SELECT * FROM users WHERE name = :name").bindparams(name=name))
    # ruleid: python.sql-injection
    db.session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))
    with db.engine.connect() as conn:
        # ok: python.sql-injection
        conn.execute(select(User).where(User.name == name))
        # ruleid: python.sql-injection
        conn.exec_driver_sql("SELECT * FROM users WHERE name = '%s'" % name)
        # ok: python.sql-injection
        conn.exec_driver_sql("SELECT * FROM users WHERE name = %(name)s", {"name": name})
    return "ok"


# GraphQL (Graphene): `execute` runs a GraphQL document, not SQL.
@app.post("/graphql")
def graphql():
    # ok: python.sql-injection
    result = schema.execute(request.json["query"])
    # ok: python.sql-injection
    result = schema.execute(request.get_json()["query"], variable_values=request.json.get("variables"))
    return {"data": result.data}


# Every HTTP method decorator of Flask, on the app and on a blueprint.
@app.put("/tags/<tag>")
def put_tag(tag):
    con = get_db()
    # ruleid: python.sql-injection
    con.execute("INSERT INTO tags (name) VALUES ('" + tag + "')")
    return "ok"


@app.patch("/tags/<tag>")
def patch_tag(tag):
    con = get_db()
    # ruleid: python.sql-injection
    con.execute("UPDATE tags SET seen = 1 WHERE name = '%s'" % tag)
    return "ok"


@app.delete("/tags/<tag>")
def delete_tag(tag):
    con = get_db()
    # ruleid: python.sql-injection
    con.execute(f"DELETE FROM tags WHERE name = '{tag}'")
    # ok: python.sql-injection
    con.execute("DELETE FROM tags WHERE name = ?", (tag,))
    return "ok"


@bp.post("/admin/users/<name>")
def admin_user(name):
    con = get_db()
    # ruleid: python.sql-injection
    con.execute("DELETE FROM users WHERE name = '" + name + "'")
    return "ok"


# Known gap: a connection from elsewhere (not a DB-API connect() or cursor() in this function),
# given a query whose text does not start with an SQL string literal, is not followed.
REPORT_QUERY = "SELECT * FROM reports WHERE name = '"


@app.route("/reports")
def reports():
    con = get_db()
    query = REPORT_QUERY + request.args["name"] + "'"
    # todoruleid: python.sql-injection
    con.execute(query)
    return "ok"


# FastAPI path operations look like Flask views to the rule: their parameters are sources,
# except those FastAPI converts (annotated int, float, bool) and dependencies (Depends()).
api = FastAPI()


class Settings:
    table = "items"


def get_settings():
    return Settings()


@api.get("/items/{item_id}")
def read_item(item_id: int, q: str = "", limit: int = 10, settings: Settings = Depends(get_settings)):
    con = get_db()
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM items WHERE note = '" + q + "'")
    # ok: python.sql-injection
    con.execute("SELECT * FROM items WHERE id = %d" % item_id)
    # ok: python.sql-injection
    con.execute("SELECT * FROM items LIMIT %d" % limit)
    # ok: python.sql-injection
    con.execute("SELECT * FROM " + settings.table + " WHERE id = ?", (item_id,))
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM items WHERE note LIKE '" + q[:20] + "%'")
    # ok: python.sql-injection
    con.execute("SELECT * FROM " + settings.table[:10])
    return {"ok": True}


# FastAPI's Annotated form, in place or through an alias.
SettingsDep = Annotated[Settings, Depends(get_settings)]


@api.get("/tables/{table_id}")
def read_table(
    table_id: Annotated[int, Path()],
    settings: SettingsDep,
    other: Annotated[Settings, Depends(get_settings)],
    note: Annotated[str, Query()] = "",
):
    con = get_db()
    # ok: python.sql-injection
    con.execute("SELECT * FROM t%d" % table_id)
    # ok: python.sql-injection
    con.execute("SELECT * FROM " + settings.table + other.table)
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM t WHERE note = '" + note + "'")
    return {"ok": True}


# A Flask view parameter annotated int is no longer a source, although Flask passes a str for a
# <name> rule without a converter.
@app.route("/legacy/<legacy_id>")
def legacy(legacy_id: int):
    con = get_db()
    # todoruleid: python.sql-injection
    con.execute("SELECT * FROM legacy WHERE id = '%s'" % legacy_id)
    return "ok"


# An allow-list: a lookup in a module-level dict of constants yields only its own values.
# Not allow-lists: a dict the module changes later, and one with a non-literal value.
SORT_COLUMNS = {"name": "name", "price": "price"}
EXTRA_COLUMNS = {"name": "name"}
DEFAULT_COLUMN = "name"
NAMED_COLUMNS = {"name": DEFAULT_COLUMN}
ALLOWED_TABLES = ("items", "orders")
RELOADED_COLUMNS = {"name": "name"}
ORDER_CLAUSES = {
    # Fixed ORDER BY clauses; the request only picks one.
    "newest": r"created_at DESC",
    "name": u"name ASC",  # a u prefix
    "quoted": "\"name\" ASC",
}
COLUMN_SETS = {"short": ("id", "name"), "long": ["id", "name", "price"]}


@app.route("/items")
def items():
    con = get_db()
    column = SORT_COLUMNS.get(request.args.get("sort"), "name")
    # ok: python.sql-injection
    con.execute("SELECT * FROM items ORDER BY " + column)
    # ok: python.sql-injection
    con.execute("SELECT * FROM items ORDER BY " + SORT_COLUMNS[request.args["sort"]])
    local_columns = {"name": request.args["fallback"]}
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM items ORDER BY " + local_columns["name"])
    FALLBACK = {"name": request.args["fallback"]}
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM items ORDER BY " + FALLBACK.get("name"))
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM items ORDER BY " + EXTRA_COLUMNS.get(request.args["sort"], "name"))
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM items ORDER BY " + NAMED_COLUMNS.get(request.args["sort"], "name"))
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM items ORDER BY " + SORT_COLUMNS.get(request.args["sort"], request.args["sort"]))
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM items ORDER BY " + RELOADED_COLUMNS.get(request.args["sort"], "name"))
    # ok: python.sql-injection
    con.execute("SELECT * FROM items ORDER BY " + ORDER_CLAUSES[request.args["o"]])
    # ok: python.sql-injection
    con.execute("SELECT * FROM items ORDER BY " + ORDER_CLAUSES.get(request.args["o"], r"id"))
    # ok: python.sql-injection
    con.execute("SELECT " + ", ".join(COLUMN_SETS[request.args["cols"]]) + " FROM items")
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM items ORDER BY " + ORDER_CLAUSES.get(request.args["o"], request.args["o"]))
    SORT_COLUMNS = {"name": request.args["fallback"]}
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM items ORDER BY " + SORT_COLUMNS["name"])
    table = request.args["table"]
    if table not in ALLOWED_TABLES:
        return "no", 400
    # todook: python.sql-injection
    con.execute("SELECT count(*) FROM " + table)
    return "ok"


@app.post("/columns")
def add_column():
    EXTRA_COLUMNS[request.form["key"]] = request.form["column"]
    return "ok"


@app.post("/columns/reload")
def reload_columns():
    global RELOADED_COLUMNS
    RELOADED_COLUMNS = dict(request.form)
    return "ok"


# A slice of request data: OpenGrep does not carry taint through a slice, so the rule takes a
# slice of a request value (in place or through a variable) or of a view parameter as request
# data itself. A slice of a value built from request data is missed.
@app.route("/prefix/<prefix>")
def by_prefix(prefix):
    con = get_db()
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM items WHERE name LIKE '" + request.args["q"][:50] + "%'")
    q = request.args.get("q", "")
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM items WHERE name LIKE '%s%%'" % q[:50])
    body = request.get_json()
    # ruleid: python.sql-injection
    con.execute(f"SELECT * FROM items WHERE note = '{body['note'][1:]}'")
    # ruleid: python.sql-injection
    con.execute("SELECT * FROM items WHERE code = '" + prefix[:3] + "'")
    # ok: python.sql-injection
    con.execute("SELECT * FROM items LIMIT %d" % int(request.args["n"][:3]))
    # ok: python.sql-injection
    con.execute("SELECT * FROM items ORDER BY " + SORT_COLUMNS.get(request.args["s"], "name")[:5])
    # todoruleid: python.sql-injection
    con.execute("SELECT * FROM items WHERE name LIKE '" + (request.args["q"] + "%")[:50] + "'")
    order = request.args.get("o", "name")
    order = SORT_COLUMNS.get(order, "name")
    # ok: python.sql-injection
    con.execute("SELECT * FROM items ORDER BY " + order[:10])
    term = request.args["q"]
    term = term.strip()
    # todoruleid: python.sql-injection
    con.execute("SELECT * FROM items WHERE name LIKE '" + term[:50] + "%'")
    return "ok"


# Django: a view receives the HttpRequest first, then the URL parts its path() or re_path()
# pattern captures as keyword arguments, e.g. path("people/<slug:slug>/", views.person_detail).
class Person(models.Model):
    last_name = models.CharField(max_length=50)
    slug = models.SlugField()


log = logging.getLogger(__name__)
PERSON_BY_NAME = "SELECT * FROM myapp_person WHERE last_name = '%s'"
PERSON_ORDERINGS = {"last": "last_name", "newest": "-id"}


def person_search(request):
    last = request.GET.get("last")
    # ruleid: python.sql-injection
    Person.objects.raw("SELECT * FROM myapp_person WHERE last_name = '%s'" % last)
    # ok: python.sql-injection
    Person.objects.raw("SELECT * FROM myapp_person WHERE last_name = %s", [last])
    # ruleid: python.sql-injection
    Person.objects.raw(PERSON_BY_NAME % last)
    # ok: python.sql-injection
    Person.objects.raw(PERSON_BY_NAME.replace("'%s'", "%s"), [last])
    # ok: python.sql-injection
    Person.objects.filter(last_name=last).order_by("slug")
    # ruleid: python.sql-injection
    Person.objects.extra(where=["last_name = '%s'" % request.GET["last"]])
    # ok: python.sql-injection
    Person.objects.extra(where=["last_name = %s"], params=[request.GET["last"]])
    # ruleid: python.sql-injection
    Person.objects.filter(slug="a").extra(select={"hit": f"last_name = '{last}'"})
    # ok: python.sql-injection
    Person.objects.extra(select={"hit": "last_name = %s"}, select_params=(last,))
    # ruleid: python.sql-injection
    Person.objects.annotate(val=RawSQL("SELECT score FROM ranks WHERE name = '" + last + "'", ()))
    # ok: python.sql-injection
    Person.objects.annotate(val=RawSQL("SELECT score FROM ranks WHERE name = %s", (last,)))
    # ok: python.sql-injection
    log.info("search", extra={"term": request.GET["last"]})
    people = Person.objects.filter(slug="a").order_by("slug")
    # ruleid: python.sql-injection
    people.extra(tables=[request.GET["table"]])
    order = PERSON_ORDERINGS.get(request.GET.get("o"), "last_name")
    # ok: python.sql-injection
    Person.objects.raw("SELECT * FROM myapp_person ORDER BY " + order)
    # ok: python.sql-injection
    Person.objects.extra(order_by=[PERSON_ORDERINGS[request.GET["o"]]])
    # ok: python.sql-injection
    Envelope().extra(where=["a = " + request.GET["last"]])
    return HttpResponse("ok")


# Not a QuerySet: a method named extra() of another class.
class Envelope:
    def extra(self, where=None):
        return where


def person_update(request):
    with connection.cursor() as cursor:
        # ruleid: python.sql-injection
        cursor.execute("UPDATE myapp_person SET seen = 1 WHERE last_name = '" + request.POST["last"] + "'")
        # ok: python.sql-injection
        cursor.execute("UPDATE myapp_person SET seen = 1 WHERE last_name = %s", [request.POST["last"]])
        # ok: python.sql-injection
        cursor.execute("UPDATE myapp_person SET seen = 1 WHERE last_name = '%s'" % request.user.get_username())
    return HttpResponse("ok")


def track_visit(request):
    with connections["default"].cursor() as cursor:
        # ruleid: python.sql-injection
        cursor.execute("INSERT INTO visits (agent) VALUES ('%s')" % request.headers["User-Agent"])
        # ruleid: python.sql-injection
        cursor.execute(f"INSERT INTO visits (referer) VALUES ('{request.META['HTTP_REFERER']}')")
        # ruleid: python.sql-injection
        cursor.execute("INSERT INTO visits (theme) VALUES ('" + request.COOKIES["theme"] + "')")
        # ruleid: python.sql-injection
        cursor.execute("INSERT INTO visits (page) VALUES ('{}')".format(request.get_full_path()))
        payload = json.loads(request.body)
        # ruleid: python.sql-injection
        cursor.execute("INSERT INTO visits (note) VALUES ('%s')" % payload["note"])
        upload = request.FILES["avatar"]
        # ruleid: python.sql-injection
        cursor.execute("INSERT INTO visits (file) VALUES ('" + upload.name + "')")
        # ok: python.sql-injection
        cursor.execute(
            "INSERT INTO visits (agent, referer) VALUES (%s, %s)",
            [request.headers["User-Agent"], request.META.get("HTTP_REFERER")],
        )
    return HttpResponse("ok")


def person_detail(request, slug):
    # ruleid: python.sql-injection
    Person.objects.raw(f"SELECT * FROM myapp_person WHERE slug = '{slug}'")
    # ok: python.sql-injection
    Person.objects.raw("SELECT * FROM myapp_person WHERE slug = %s", [slug])
    return HttpResponse("ok")


def person_prefix(request, slug):
    payload = json.loads(request.body)
    with connection.cursor() as cursor:
        # ruleid: python.sql-injection
        cursor.execute("SELECT * FROM myapp_person WHERE last_name LIKE '" + request.GET["q"][:20] + "%'")
        # ruleid: python.sql-injection
        cursor.execute("SELECT * FROM myapp_person WHERE slug = '" + slug[:20] + "'")
        # ruleid: python.sql-injection
        cursor.execute("SELECT * FROM myapp_person WHERE note = '%s'" % payload["note"][:100])
    return HttpResponse("ok")


# A local named request in a helper that is not a view: an outgoing urllib request.
def fetch_remote(url):
    request = urllib.request.Request(url)
    with connection.cursor() as cursor:
        # ok: python.sql-injection
        cursor.execute("INSERT INTO fetches (agent) VALUES ('" + request.headers["User-Agent"][:20] + "')")
    return url


# path("people/<int:pk>/", views.person_by_id): the int converter hands the view an int, but the
# URL configuration is in another module, so the rule cannot see it.
def person_by_id(request, pk):
    # todook: python.sql-injection
    Person.objects.raw("SELECT * FROM myapp_person WHERE id = %s" % pk)
    # ok: python.sql-injection
    Person.objects.raw("SELECT * FROM myapp_person WHERE id = %d" % int(pk))
    return HttpResponse("ok")


# Class-based views: dispatch() calls the method named after the HTTP method; setup() keeps the
# request and the URL arguments on self.request, self.args and self.kwargs.
class PersonView(View):
    def get(self, request, slug):
        with connection.cursor() as cursor:
            # ruleid: python.sql-injection
            cursor.execute("SELECT * FROM myapp_person WHERE slug = '" + slug + "'")
            # ruleid: python.sql-injection
            cursor.execute("SELECT * FROM myapp_person WHERE slug = '%s'" % self.kwargs["slug"])
            # ruleid: python.sql-injection
            cursor.execute("SELECT * FROM myapp_person WHERE last_name LIKE '" + self.request.GET["q"][:20] + "%'")
            # ok: python.sql-injection
            cursor.execute("SELECT * FROM myapp_person WHERE slug = %s", [self.kwargs["slug"]])
        # ruleid: python.sql-injection
        Person.objects.extra(where=[f"last_name = '{self.request.GET['q']}'"])
        return HttpResponse("ok")

    def get_queryset(self):
        # ruleid: python.sql-injection
        return Person.objects.all().extra(where=["slug = '%s'" % self.kwargs["slug"]])

    def visible(self):
        # ruleid: python.sql-injection
        return self.get_queryset().filter(slug="a").extra(select={"q": self.request.GET["q"]})

    def post(self, request, *args, **kwargs):
        # ruleid: python.sql-injection
        Person.objects.raw("SELECT * FROM myapp_person WHERE last_name = '%s'" % request.POST["last"])
        # ok: python.sql-injection
        Person.objects.raw("SELECT * FROM myapp_person WHERE last_name = %s", [request.POST["last"]])
        # ruleid: python.sql-injection
        Person.objects.raw("SELECT * FROM myapp_person WHERE slug = '%s'" % kwargs["slug"])
        return HttpResponse("ok")


# A helper in a Django module whose first parameter is named request looks like a view: its
# other parameters are taken for URL arguments even when the caller passes its own values.
def count_rows(request, table_name):
    with connection.cursor() as cursor:
        # todook: python.sql-injection
        cursor.execute("SELECT count(*) FROM " + table_name)
    return HttpResponse("ok")


# The same helper shape with an outgoing request of an HTTP client (requests.PreparedRequest):
# its headers are taken for the incoming request's.
def audit_outgoing(request):
    with connection.cursor() as cursor:
        # todook: python.sql-injection
        cursor.execute("INSERT INTO audit (agent) VALUES ('" + request.headers["User-Agent"] + "'")
    return request


# A view argument with a default value is a source too: Django passes it from the URL when the
# pattern captures it ("Specifying defaults for view arguments"), and from path()'s kwargs or
# the default otherwise.
def person_page(request, per_page=10):
    # todook: python.sql-injection
    Person.objects.raw("SELECT * FROM myapp_person LIMIT %s" % per_page)
    return HttpResponse("ok")


# re_path(r"^archive/(?P<year>[0-9]{4})/$", views.archive): re_path() passes strings.
def archive(request, **kwargs):
    with connection.cursor() as cursor:
        # ruleid: python.sql-injection
        cursor.execute("SELECT * FROM myapp_person WHERE year = '" + kwargs["year"] + "'")
        # ok: python.sql-injection
        cursor.execute("SELECT * FROM myapp_person WHERE year = %s", [kwargs["year"]])
    return HttpResponse("ok")
