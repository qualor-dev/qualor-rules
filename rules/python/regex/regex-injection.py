import json
import re
from typing import Annotated

from django.http import HttpResponse, JsonResponse
from django.views import View
from fastapi import Depends, FastAPI, Path, Query, Request
from flask import Flask, abort, request
from pydantic import BaseModel

app = Flask(__name__)
api = FastAPI()

ARTICLES = ["first post", "second post"]
FILTERS = {
    # Patterns a client may pick; the request only chooses one.
    "digits": r"\d+",
    "words": r"\w+",  # the default
}
SPLITTERS = {"csv": (",", ";"), "space": [r"\s+"]}
SLUG = r"^[a-z0-9-]+$"
# A nested table is not recognised as an allow-list.
NESTED_FILTERS = {"date": {"iso": r"\d{4}-\d{2}-\d{2}"}}
# Changed later by a view, so not an allow-list.
SAVED_FILTERS = {"recent": r"20\d\d"}


# Flask: query strings, form fields, JSON bodies, headers, cookies, URL variables.
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # ruleid: python.regex-injection
    pattern = re.compile(q, re.IGNORECASE)
    return str([a for a in ARTICLES if pattern.search(a)])


@app.route("/grep/<expr>")
def grep(expr):
    # ruleid: python.regex-injection
    return str([a for a in ARTICLES if re.search(expr, a)])


@app.post("/validate")
def validate():
    body = request.get_json()
    # ruleid: python.regex-injection
    ok = re.fullmatch(body["rule"], body["value"]) is not None
    # ruleid: python.regex-injection
    starts = re.match("^" + request.form["prefix"], "some text")
    # ruleid: python.regex-injection
    parts = re.split(f"[{request.headers['X-Separators']}]", "a,b;c")
    return str((ok, starts, parts))


@app.route("/highlight")
def highlight():
    term = request.cookies["term"]
    # A length check does not stop a short catastrophic pattern such as (a+)+$.
    if len(term) > 40:
        abort(400)
    # ruleid: python.regex-injection
    marked = re.sub("(%s)" % term, r"<mark>\1</mark>", "text")
    # ruleid: python.regex-injection
    count = re.subn(pattern=request.values["p"], repl="", string="text")
    # ruleid: python.regex-injection
    words = re.findall(r"\b" + term + r"\w*", "text")
    # ruleid: python.regex-injection
    spans = [m.span() for m in re.finditer("{}+".format(request.args["ch"]), "text")]
    return str((marked, count, words, spans))


# Flask: re.escape(), request data as the subject or replacement, constants, allow-lists.
@app.route("/search-safe")
def search_safe():
    q = request.args.get("q", "")
    # ok: python.regex-injection
    a = re.compile(re.escape(q), re.IGNORECASE)
    # ok: python.regex-injection
    b = re.search(r"\b" + re.escape(q) + r"\b", "text")
    # ok: python.regex-injection
    c = re.compile("|".join(map(re.escape, request.args.getlist("w"))))
    # ok: python.regex-injection
    d = re.fullmatch(SLUG, request.args["slug"])
    # ok: python.regex-injection
    e = re.sub(r"\s+", request.args["sep"], q)
    # ok: python.regex-injection
    f = re.split(r",", request.form["tags"])
    # ok: python.regex-injection
    g = re.compile(r"\d{%d}" % int(request.args["len"]))
    # ok: python.regex-injection
    h = re.compile("|".join(re.escape(w) for w in request.args.getlist("w")))
    return str((a, b, c, d, e, f, g, h))


@app.route("/filter/<kind>")
def filter_view(kind):
    # ok: python.regex-injection
    a = re.findall(FILTERS.get(kind, FILTERS["words"]), request.args["text"])
    # ok: python.regex-injection
    b = re.split("|".join(SPLITTERS[kind]), request.args["text"])
    # ok: python.regex-injection
    c = re.compile(FILTERS[kind] if kind in FILTERS else SLUG)
    # ok: python.regex-injection
    c2 = re.compile(FILTERS.get(kind, r"[^,]+"))
    # ruleid: python.regex-injection
    d = re.compile(FILTERS.get(kind, request.args["custom"]))
    # ruleid: python.regex-injection
    e = re.compile(SAVED_FILTERS[kind])
    # todook: python.regex-injection
    f = re.compile(NESTED_FILTERS["date"][kind])
    DEFAULT_FILTER = request.args["default"]
    # ruleid: python.regex-injection
    g = re.compile(FILTERS.get(kind, DEFAULT_FILTER))
    return str((a, b, c, d, e, f, g))


@app.post("/filters")
def save_filter():
    SAVED_FILTERS[request.form["name"]] = request.form["pattern"]
    return "ok"


# Look-alikes: str.split()/replace(), a search index, a compiled constant pattern's methods.
@app.route("/lookalikes")
def lookalikes():
    q = request.args["q"]
    # ok: python.regex-injection
    a = "a,b,c".split(q)
    # ok: python.regex-injection
    b = "text".replace(q, "")
    # ok: python.regex-injection
    c = index.search(q)
    # ok: python.regex-injection
    d = re.compile(SLUG).match(q)
    return str((a, b, c, d))


index = None


# A membership check against an allow-list is not recognised.
@app.route("/mode")
def mode():
    m = request.args["mode"]
    if m not in ("a", "b"):
        return "bad", 400
    # todook: python.regex-injection
    return str(re.compile("^" + m + "+$"))


# A pattern first checked against a constant regex (only letters, digits and spaces) is not
# recognised either.
@app.route("/word")
def word():
    w = request.args["w"]
    if not re.fullmatch(r"[\w ]+", w):
        return "bad", 400
    # todook: python.regex-injection
    return str(re.compile(r"\b" + w + r"\b"))


# A slice of request data: OpenGrep does not carry taint through a slice, so the rule takes a
# slice of a request value (in place or through a variable) or of a view parameter as request
# data itself. A slice of a value built from request data is missed.
@app.route("/short")
def short():
    q = request.args["q"]
    # ruleid: python.regex-injection
    re.search(q[:20], "text")
    # todoruleid: python.regex-injection
    re.compile(("^" + request.args["q"])[:20])
    trimmed = request.args["q"]
    trimmed = trimmed.strip()
    # todoruleid: python.regex-injection
    re.search(trimmed[:20], "text")
    # ruleid: python.regex-injection
    return str(re.compile(request.args["q"][:20]))


# Flask typed converter: the rule cannot see that <int:n> is an int.
@app.route("/repeat/<int:n>")
def repeat(n):
    # todook: python.regex-injection
    return str(re.compile(r"\d{%s}" % n))


# A Flask view parameter annotated int is not a source, although Flask passes a str for a
# <name> rule without a converter.
@app.route("/legacy/<legacy_expr>")
def legacy(legacy_expr: int):
    # todoruleid: python.regex-injection
    return str(re.compile(legacy_expr))


# Django: GET, POST, body, URL arguments, class-based views.
def django_search(request):
    # ruleid: python.regex-injection
    hits = [a for a in ARTICLES if re.search(request.GET["q"], a)]
    return JsonResponse({"hits": hits})


def django_split(request, sep):
    payload = json.loads(request.body)
    # ruleid: python.regex-injection
    parts = re.split(sep, payload["text"])
    # ruleid: python.regex-injection
    rule = re.compile(payload["rule"])
    return HttpResponse(str((parts, rule)))


class MatchView(View):
    def post(self, request):
        # ruleid: python.regex-injection
        m = re.match(self.request.POST["pattern"], "text")
        # ok: python.regex-injection
        safe = re.match(re.escape(self.request.POST["pattern"]), "text")
        return HttpResponse(str((m, safe)))


# path("repeat/<int:pk>/", views.django_repeat): the converter is in urls.py.
def django_repeat(request, pk):
    # todook: python.regex-injection
    return HttpResponse(str(re.compile(r"\d{%s}" % pk)))


# A default value: Django passes the URL value when the pattern captures one.
def django_default(request, sep=","):
    # todook: python.regex-injection
    return HttpResponse(str(re.split(sep, "a,b")))


# Helpers whose first parameter is named request look like views: other parameters count as URL
# arguments, and an outgoing request (an HTTP client's) has its headers taken as request data.
def match_for(request, expr):
    # todook: python.regex-injection
    return re.compile(expr)


def match_header(request):
    # todook: python.regex-injection
    return re.compile(request.headers["X-Pattern"])


# FastAPI: query and path parameters, bodies, the Request object.
class Rule(BaseModel):
    name: str
    pattern: str


@api.post("/rules/{field}")
async def create_rule(field: str, rule: Rule, request: Request, flags: str = ""):
    # ruleid: python.regex-injection
    a = re.compile(rule.pattern)
    # ruleid: python.regex-injection
    b = re.search(field + "=.*", "x")
    # ruleid: python.regex-injection
    c = re.compile(flags)
    # ruleid: python.regex-injection
    d = re.compile(request.query_params["re"])
    # ok: python.regex-injection
    e = re.fullmatch(r"[A-Za-z_]+", rule.name)
    return {"ok": all((a, b, c, d, e))}


class Settings(BaseModel):
    name_pattern: str = r"^[a-z]+$"


def get_settings():
    return Settings()


SettingsDep = Annotated[Settings, Depends(get_settings)]


@api.get("/digits/{n}")
async def digits(
    n: Annotated[int, Path()],
    settings: SettingsDep,
    other: Annotated[Settings, Depends(get_settings)],
    legacy: Settings = Depends(get_settings),
    sep: Annotated[str, Query()] = ",",
):
    # ok: python.regex-injection
    a = re.compile(settings.name_pattern)
    # ok: python.regex-injection
    b = re.compile(other.name_pattern + legacy.name_pattern)
    # ok: python.regex-injection
    c = re.compile(r"\d{" + str(n) + "}")
    # ruleid: python.regex-injection
    d = re.split(sep, "a,b")
    return {"ok": all((a, b, c, d))}
