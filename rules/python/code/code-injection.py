from starlette.middleware.base import BaseHTTPMiddleware
import ast
import builtins
import json
import re
from typing import Annotated

from django.http import HttpResponse, JsonResponse
from django.views import View
from fastapi import Depends, FastAPI, Path, Query, Request
from flask import Flask, request
from pydantic import BaseModel

app = Flask(__name__)
api = FastAPI()

FORMULAS = {
    # Pricing formulas the app offers; the request only picks one.
    "net": "price * qty",
    "gross": "price * qty * 1.2",  # with VAT
}
SNIPPETS = {"greet": ("name = 'world'", "message = 'hello ' + name"), "noop": ["pass"]}
REPORT_SCRIPT = "total = sum(values)"
CHECKS = {"positive": "value > 0", "escaped": "name == \"admin\""}
# A nested table is not recognised as an allow-list.
NESTED_FORMULAS = {"tax": {"de": "price * 0.19"}}
# Changed later by a view, so not an allow-list.
MACROS = {"double": "x * 2"}


# Flask: query strings, form fields, JSON bodies, headers, cookies, uploaded files, URL variables.
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1 + 1")
    # ruleid: python.code-injection
    return str(eval(expr))


@app.post("/run")
def run():
    # ruleid: python.code-injection
    exec(request.form["code"])
    # ruleid: python.code-injection
    exec(request.files["script"].read())
    return "ok"


@app.post("/rules")
def rules():
    body = request.get_json()
    # ruleid: python.code-injection
    check = eval("lambda order: " + body["condition"])
    # ruleid: python.code-injection
    code = compile(f"result = {body['formula']}", "<formula>", "exec")
    # ruleid: python.code-injection
    exec(code)
    return "ok"


@app.route("/hook")
def hook():
    # ruleid: python.code-injection
    eval(request.headers["X-Hook"])
    # ruleid: python.code-injection
    builtins.exec(request.cookies["script"])
    return "ok"


@app.route("/fn/<name>")
def fn(name):
    # ruleid: python.code-injection
    return str(eval("handle_%s()" % name))


# Flask: literal evaluation, data only in the namespace or the file name, conversions, allow-lists.
@app.route("/calc-safe")
def calc_safe():
    # ok: python.code-injection
    a = ast.literal_eval(request.args["value"])
    # ok: python.code-injection
    b = json.loads(request.args["value"])
    # ok: python.code-injection
    c = eval("price * qty", {"__builtins__": {}}, {"price": float(request.args["p"]), "qty": request.args["q"]})
    # ok: python.code-injection
    exec(REPORT_SCRIPT, {"values": request.get_json()["values"]})
    # ok: python.code-injection
    d = compile(REPORT_SCRIPT, request.args.get("name", "<report>"), "exec")
    # ok: python.code-injection
    e = eval(f"{int(request.args['n'])} * 2")
    # ok: python.code-injection
    f = eval("1 + 1")
    return str((a, b, c, d, e, f))


@app.route("/formula/<kind>")
def formula(kind):
    # ok: python.code-injection
    a = eval(FORMULAS.get(kind, FORMULAS["net"]), {"__builtins__": {}}, {"price": 2, "qty": 3})
    # ok: python.code-injection
    exec("\n".join(SNIPPETS[kind]))
    # ok: python.code-injection
    b = eval(FORMULAS[kind] if kind in FORMULAS else "0")
    # ruleid: python.code-injection
    c = eval(FORMULAS.get(kind, request.args["formula"]))
    # A constant key with request data as the default.
    fallbacks = {"unused": ""}
    default_choice = fallbacks.get("net", request.args["formula"])
    # ruleid: python.code-injection
    c3 = eval(default_choice)
    options = {"expr": "1 + 1"}
    options.get("label", request.args["label"])
    # A get() with request data as its key or default makes the dict request data for the rest
    # of the function, so a later lookup of a constant entry is reported.
    # todook: python.code-injection
    h = eval(options.get("expr"))
    # Request data written into a dict and read back through get(), and a pop() or setdefault()
    # whose key or default is request data.
    written = {"default": "1 + 1"}
    written["custom"] = request.args["o"]
    # ruleid: python.code-injection
    eval(written.get("custom"))
    popped = {"default": "1 + 1"}
    # ruleid: python.code-injection
    eval(popped.pop(request.args["o"]))
    pop_default = {"default": "1 + 1"}
    # ruleid: python.code-injection
    eval(pop_default.pop("custom", request.args["o"]))
    set_key = {"default": "1 + 1"}
    # ruleid: python.code-injection
    eval(set_key.setdefault(request.args["o"]))
    set_default = {"default": "1 + 1"}
    # ruleid: python.code-injection
    eval(set_default.setdefault("custom", request.args["o"]))
    # An item set to request data makes the dict request data for the rest of the function too.
    # todook: python.code-injection
    eval(written.get("default"))
    # get() by request data on a table that request data changes elsewhere in the file.
    stored_choice = MACROS.get(kind)
    # ruleid: python.code-injection
    d2 = eval(stored_choice, {"x": 2})
    # ruleid: python.code-injection
    d = eval(MACROS[kind], {"x": 2})
    # ok: python.code-injection
    e = eval(CHECKS[kind], {"__builtins__": {}}, {"value": 1, "name": "x"})
    # todook: python.code-injection
    f = eval(NESTED_FORMULAS[kind]["de"], {"price": 2})
    DEFAULT_FORMULA = request.args["formula"]
    # ruleid: python.code-injection
    g = eval(FORMULAS.get(kind, DEFAULT_FORMULA))
    return str((a, b, c, d, e, f, g))


@app.post("/macros")
def add_macro():
    MACROS[request.form["name"]] = request.form["body"]
    return "ok"


# Look-alikes: eval()/compile() methods of other objects and re.compile().
@app.route("/lookalikes")
def lookalikes():
    model = load_model()
    # ok: python.code-injection
    model.eval()
    # ok: python.code-injection
    pattern = re.compile(request.args["pattern"])
    # ok: python.code-injection
    result = scripts.eval(request.args["script"], 0)
    return str((pattern, result))


def load_model():
    return None


scripts = None


# A membership check against an allow-list is not recognised.
@app.route("/op")
def op():
    o = request.args["op"]
    if o not in ("+", "-", "*"):
        return "bad", 400
    # todook: python.code-injection
    return str(eval("2 " + o + " 3"))


# A slice of request data: OpenGrep does not carry taint through a slice, so the rule takes a
# slice of a request value (in place or through a variable) or of a view parameter as request
# data itself. A slice of a value built from request data is missed.
@app.route("/short")
def short():
    expr = request.args["expr"]
    # ruleid: python.code-injection
    eval(expr[:20])
    # todoruleid: python.code-injection
    eval((request.args["expr"] + " + 0")[:20])
    trimmed = request.args["expr"]
    trimmed = trimmed.strip()
    # todoruleid: python.code-injection
    eval(trimmed[:20])
    # ruleid: python.code-injection
    return str(eval(request.args["expr"][:20]))


# Flask typed converter: the rule cannot see that <int:n> is an int.
@app.route("/square/<int:n>")
def square(n):
    # todook: python.code-injection
    return str(eval("%s ** 2" % n))


# A Flask view parameter annotated int is not a source, although Flask passes a str for a
# <name> rule without a converter.
@app.route("/legacy/<legacy_expr>")
def legacy(legacy_expr: int):
    # todoruleid: python.code-injection
    return str(eval(legacy_expr))


# Django: GET, POST, body, URL arguments, class-based views.
def django_calc(request):
    # ruleid: python.code-injection
    return HttpResponse(str(eval(request.GET["expr"])))


def django_run(request, script_name):
    payload = json.loads(request.body)
    # ruleid: python.code-injection
    exec(payload["code"])
    # ruleid: python.code-injection
    exec("from tasks import " + script_name)
    return JsonResponse({"ok": True})


class FormulaView(View):
    def post(self, request):
        # ruleid: python.code-injection
        value = eval(self.request.POST["formula"], {"__builtins__": {}})
        # ok: python.code-injection
        safe = ast.literal_eval(self.request.POST["formula"])
        return JsonResponse({"value": value, "safe": safe})


# path("square/<int:pk>/", views.django_square): the converter is in urls.py.
def django_square(request, pk):
    # todook: python.code-injection
    return HttpResponse(str(eval("%s ** 2" % pk)))


# A function named like a class-based view's handler (get, post, ...) that takes (self, request,
# ...) is taken for one also outside a class: its parameters after request count as URL arguments.
def get(self, request, pk):
    # todook: python.code-injection
    return HttpResponse(str(eval("%s ** 2" % pk)))


# A default value: Django passes the URL value when the pattern captures one.
def django_default(request, expr="1"):
    # todook: python.code-injection
    return HttpResponse(str(eval(expr)))


# Helpers whose first parameter is named request look like views: other parameters count as URL
# arguments, and an outgoing request (an HTTP client's) has its headers taken as request data.
def evaluate_for(request, source):
    # todook: python.code-injection
    return eval(source)


def evaluate_header(request):
    # todook: python.code-injection
    return eval(request.headers["X-Expr"])


# FastAPI: query and path parameters, bodies, the Request object.
class Rule(BaseModel):
    name: str
    condition: str


@api.post("/rules/{rule_id}")
async def create_rule(rule_id: str, rule: Rule, request: Request, debug: str = ""):
    # ruleid: python.code-injection
    check = eval("lambda item: " + rule.condition)
    # ruleid: python.code-injection
    exec(debug)
    # ruleid: python.code-injection
    exec((await request.body()).decode())
    # ruleid: python.code-injection
    compile(rule_id, "<rule>", "eval")
    return {"ok": True}


class Settings(BaseModel):
    discount_formula: str = "price * 0.9"


def get_settings():
    return Settings()


SettingsDep = Annotated[Settings, Depends(get_settings)]


@api.get("/price/{price}")
async def price(
    price: Annotated[int, Path()],
    settings: SettingsDep,
    other: Annotated[Settings, Depends(get_settings)],
    legacy: Settings = Depends(get_settings),
    expr: Annotated[str, Query()] = "",
):
    # ok: python.code-injection
    a = eval(settings.discount_formula, {"__builtins__": {}}, {"price": price})
    # ok: python.code-injection
    b = eval(other.discount_formula)
    # ok: python.code-injection
    c = eval(legacy.discount_formula)
    # ok: python.code-injection
    d = eval(str(price) + " * 2")
    # ruleid: python.code-injection
    e = eval(expr)
    return {"price": a}


# Middleware runs for every request and is not a view: a Starlette BaseHTTPMiddleware's
# dispatch() and a FastAPI @app.middleware("http") function.
class CalcMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, incoming, call_next):
        # ruleid: python.code-injection
        eval(incoming.query_params["q"])
        # ruleid: python.code-injection
        eval(incoming.path_params["item"])
        # ruleid: python.code-injection
        eval(incoming.headers["X-Value"])
        # ruleid: python.code-injection
        eval(incoming.cookies["value"])
        # ruleid: python.code-injection
        eval(incoming.url.query)
        # ruleid: python.code-injection
        eval(str(incoming.url))
        # ruleid: python.code-injection
        eval(f"{incoming.url}")
        # ruleid: python.code-injection
        eval(incoming.url.hostname)
        # ruleid: python.code-injection
        eval((await incoming.body()).decode())
        # The scheme is http or https; the port is a number.
        # ok: python.code-injection
        eval(incoming.url.scheme)
        # ok: python.code-injection
        eval(str(incoming.url.port))
        # ok: python.code-injection
        eval(str(incoming.url.is_secure))
        return await call_next(incoming)


@api.middleware("http")
async def calc_middleware(incoming, call_next):
    # ruleid: python.code-injection
    eval(incoming.url.path)
    # ruleid: python.code-injection
    eval(incoming.url.path[1:])
    # ruleid: python.code-injection
    eval(incoming.url.path[:64])
    # ruleid: python.code-injection
    eval(incoming.url.path[1:64])
    # ruleid: python.code-injection
    eval((await incoming.json())["value"])
    # ruleid: python.code-injection
    eval((await incoming.form())["value"])
    async for chunk in incoming.stream():
        # ruleid: python.code-injection
        eval(chunk.decode())
    # A slice of a middleware value other than the path, in place or through a variable, is
    # missed.
    # todoruleid: python.code-injection
    eval(incoming.query_params["q"][:40])
    return await call_next(incoming)


# Not middleware: a dispatch() method of a class that is not a BaseHTTPMiddleware.
class CalcRouter:
    async def dispatch(self, incoming, call_next):
        # ok: python.code-injection
        eval(incoming.query_params["q"])
        # ok: python.code-injection
        eval(incoming.url.path)
        # ok: python.code-injection
        eval(incoming.url.query)
        # ok: python.code-injection
        eval(str(incoming.url))
        # ok: python.code-injection
        eval(incoming.url.hostname)
        async for chunk in incoming.stream():
            # ok: python.code-injection
            eval(chunk.decode())
        # ok: python.code-injection
        eval(incoming.path_params["item"])
        # ok: python.code-injection
        eval(incoming.headers["X-Value"])
        # ok: python.code-injection
        eval(incoming.cookies["value"])
        # ok: python.code-injection
        eval((await incoming.json())["value"])
        # ok: python.code-injection
        eval((await incoming.body()).decode())
        # ok: python.code-injection
        eval((await incoming.form())["value"])
        # ok: python.code-injection
        eval(incoming.url.path[1:])
        # ok: python.code-injection
        eval(incoming.url.path[:64])
        # ok: python.code-injection
        eval(incoming.url.path[1:64])


# A Flask before_request hook reads flask.request.
@app.before_request
def calc_hook():
    # ruleid: python.code-injection
    eval(request.args["q"])
