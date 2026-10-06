import json
import string
from typing import Annotated

import jinja2
from jinja2.nativetypes import NativeEnvironment
from jinja2.sandbox import ImmutableSandboxedEnvironment, SandboxedEnvironment
from django.http import HttpResponse
from django.shortcuts import render
from django.template import Context, Engine, Template, engines
from django.views import View
from fastapi import Depends, FastAPI, Path, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from flask import Flask, current_app, render_template, render_template_string, request, stream_template_string
from markupsafe import escape
from pydantic import BaseModel

app = Flask(__name__)
api = FastAPI()
templates = Jinja2Templates(directory="templates")
env = jinja2.Environment(autoescape=True)
sandbox = SandboxedEnvironment(autoescape=True)

GREETINGS = {
    # One greeting per language; the request only picks one.
    "en": "Hello {{ name }}!",
    "de": "Hallo {{ name }}!",  # the default
}
LAYOUTS = {"card": ("<div>", "{{ body }}", "</div>"), "plain": ["{{ body }}"]}
PAGE = "<h1>{{ title }}</h1>"
# A nested table is not recognised as an allow-list.
NESTED_GREETINGS = {"formal": {"en": "Dear {{ name }}"}}
# Changed later by a view, so not an allow-list.
SNIPPETS = {"footer": "<footer>{{ year }}</footer>"}


# Flask: query strings, form fields, JSON bodies, headers, cookies, URL variables.
@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    # ruleid: python.template-injection
    return render_template_string("<p>Hello " + name + "!</p>")


@app.route("/greet/<name>")
def greet(name):
    # ruleid: python.template-injection
    return render_template_string(f"<h1>Welcome, {name}</h1>")


@app.post("/preview")
def preview():
    body = request.get_json()
    # ruleid: python.template-injection
    html = render_template_string(body["template"], user="guest")
    # ruleid: python.template-injection
    stream = stream_template_string(source=request.form["tpl"])
    return html


@app.route("/error")
def error():
    # ruleid: python.template-injection
    return render_template_string("<p>Not found: %s</p>" % request.headers["Referer"]), 404


@app.route("/banner")
def banner():
    # HTML escaping does not touch the template's {{ }} delimiters.
    # ruleid: python.template-injection
    return render_template_string("<div>{}</div>".format(escape(request.cookies["banner"])))


@app.route("/mail")
def mail():
    tpl = request.args["tpl"]
    # ruleid: python.template-injection
    t = jinja2.Template(tpl)
    # ruleid: python.template-injection
    a = env.from_string(tpl)
    # ruleid: python.template-injection
    b = jinja2.Environment().from_string(source=request.args["subject"])
    # ruleid: python.template-injection
    c = current_app.jinja_env.from_string(tpl)
    # ruleid: python.template-injection
    d = app.jinja_env.from_string("{% extends 'base.html' %}" + tpl)
    # ruleid: python.template-injection
    e = NativeEnvironment().from_string(request.args["expr"])
    return t.render() + a.render() + b.render() + c.render() + d.render() + str(e.render())


@app.route("/report")
def report():
    local_env = jinja2.Environment(loader=jinja2.FileSystemLoader("templates"))
    # ruleid: python.template-injection
    return local_env.from_string(request.values["layout"]).render(rows=[])


# Flask: request data as context, constants, the sandbox, allow-lists, look-alikes.
@app.route("/hello-safe")
def hello_safe():
    name = request.args.get("name", "world")
    # ok: python.template-injection
    a = render_template_string("<p>Hello {{ name }}!</p>", name=name)
    # ok: python.template-injection
    b = render_template_string(PAGE, title=request.args["title"], **request.args)
    # ok: python.template-injection
    c = render_template("hello.html", name=name)
    # ok: python.template-injection
    d = jinja2.Template("Hello {{ name }}").render(name=name)
    # ok: python.template-injection
    e = env.from_string("{{ greeting }}, {{ name }}").render(greeting=request.args["g"], name=name)
    # ok: python.template-injection
    f = render_template_string("<p>Page %d</p>" % int(request.args["page"]))
    return a + b + c + d + e + f


@app.route("/sandbox")
def sandboxed():
    # ok: python.template-injection
    a = sandbox.from_string(request.args["tpl"]).render(user="guest")
    # ok: python.template-injection
    b = SandboxedEnvironment().from_string(request.form["tpl"]).render()
    # ok: python.template-injection
    c = ImmutableSandboxedEnvironment().from_string(request.get_json()["tpl"]).render()
    return a + b + c


@app.route("/greeting/<lang>")
def greeting(lang):
    # ok: python.template-injection
    a = render_template_string(GREETINGS.get(lang, GREETINGS["de"]), name=request.args["n"])
    # ok: python.template-injection
    b = render_template_string("".join(LAYOUTS[lang]), body=request.args["b"])
    # ok: python.template-injection
    c = render_template_string(GREETINGS[lang] if lang in GREETINGS else PAGE, name="x")
    # ruleid: python.template-injection
    d = render_template_string(GREETINGS.get(lang, request.args["fallback"]))
    # ruleid: python.template-injection
    e = render_template_string(SNIPPETS[lang], year=2026)
    # todook: python.template-injection
    f = render_template_string(NESTED_GREETINGS["formal"][lang], name="x")
    DEFAULT_GREETING = request.args["greeting"]
    # ruleid: python.template-injection
    g = render_template_string(GREETINGS.get(lang, DEFAULT_GREETING))
    return a + b + c + d + e + f + g


@app.post("/snippets")
def add_snippet():
    SNIPPETS[request.form["name"]] = request.form["body"]
    return "ok"


# Look-alikes: string.Template only substitutes $names; a template name picks a file of the
# app's own template folder; from_string() of another library.
@app.route("/lookalikes")
def lookalikes():
    # ok: python.template-injection
    a = string.Template(request.args["fmt"]).safe_substitute(name="x")
    # ok: python.template-injection
    b = render_template(request.args["page"] + ".html")
    # ok: python.template-injection
    c = env.get_template(request.args["page"]).render()
    # ok: python.template-injection
    d = json_schema.from_string(request.args["schema"])
    return a + b + c + str(d)


json_schema = None


# A membership check against an allow-list is not recognised.
@app.route("/theme")
def theme():
    t = request.args["theme"]
    if t not in ("light", "dark"):
        return "bad", 400
    # todook: python.template-injection
    return render_template_string("<body class='" + t + "'>{{ body }}</body>", body="x")


# A slice of request data: OpenGrep does not carry taint through a slice, so the rule takes a
# slice of a request value (in place or through a variable) or of a view parameter as request
# data itself. A slice of a value built from request data is missed.
@app.route("/short")
def short():
    tpl = request.args["tpl"]
    # ruleid: python.template-injection
    render_template_string(tpl[:200])
    # todoruleid: python.template-injection
    render_template_string(("<p>" + request.args["tpl"])[:200])
    trimmed = request.args["tpl"]
    trimmed = trimmed.strip()
    # todoruleid: python.template-injection
    render_template_string(trimmed[:200])
    # ruleid: python.template-injection
    return render_template_string(request.args["tpl"][:200])


# An environment received as a parameter or built by a helper is not known to be Jinja's.
def build_env():
    return jinja2.Environment()


@app.route("/helper-env")
def helper_env():
    helper = build_env()
    # todoruleid: python.template-injection
    return helper.from_string(request.args["tpl"]).render()


def render_with(given_env):
    # todoruleid: python.template-injection
    return given_env.from_string(request.args["tpl"]).render()


# Flask typed converter: the rule cannot see that <int:n> is an int.
@app.route("/count/<int:n>")
def count(n):
    # todook: python.template-injection
    return render_template_string("<p>%s items</p>" % n)


# A Flask view parameter annotated int is not a source, although Flask passes a str for a
# <name> rule without a converter.
@app.route("/legacy/<legacy_tpl>")
def legacy(legacy_tpl: int):
    # todoruleid: python.template-injection
    return render_template_string(legacy_tpl)


# Django: GET, POST, body, URL arguments, class-based views.
def django_hello(request):
    # ruleid: python.template-injection
    t = Template("<p>Hello " + request.GET["name"] + "</p>")
    return HttpResponse(t.render(Context({})))


def django_page(request, slug):
    payload = json.loads(request.body)
    # ruleid: python.template-injection
    a = engines["django"].from_string(payload["template"])
    django_engine = engines["jinja2"]
    # ruleid: python.template-injection
    b = django_engine.from_string("<h1>%s</h1>" % slug)
    # ruleid: python.template-injection
    c = Engine.get_default().from_string(request.POST["tpl"])
    return HttpResponse(a.render({}) + b.render({}) + c.render(Context({})))


class PreviewView(View):
    def post(self, request):
        engine = Engine(debug=False)
        # ruleid: python.template-injection
        t = engine.from_string(self.request.POST["template"])
        return HttpResponse(t.render(Context({})))


def django_safe(request):
    # ok: python.template-injection
    a = Template("<p>Hello {{ name }}</p>").render(Context({"name": request.GET["name"]}))
    # ok: python.template-injection
    b = engines["django"].from_string("{{ q }}").render({"q": request.GET.get("q")})
    # ok: python.template-injection
    c = render(request, "page.html", {"q": request.GET.get("q")})
    return HttpResponse(a + b + c.content.decode())


# path("count/<int:pk>/", views.django_count): the converter is in urls.py.
def django_count(request, pk):
    # todook: python.template-injection
    return HttpResponse(Template("<p>%s</p>" % pk).render(Context({})))


# A default value: Django passes the URL value when the pattern captures one.
def django_default(request, layout="plain"):
    # todook: python.template-injection
    return HttpResponse(Template(layout).render(Context({})))


# Helpers whose first parameter is named request look like views: other parameters count as URL
# arguments, and an outgoing request (an HTTP client's) has its headers taken as request data.
def render_for(request, source):
    # todook: python.template-injection
    return Template(source).render(Context({}))


def render_header(request):
    # todook: python.template-injection
    return Template(request.headers["X-Template"]).render(Context({}))


# FastAPI: query and path parameters, bodies, the Request object, Jinja2Templates.env.
class Message(BaseModel):
    subject: str
    body: str


@api.post("/messages/{kind}", response_class=HTMLResponse)
async def message(kind: str, msg: Message, request: Request, signature: str = ""):
    # ruleid: python.template-injection
    a = templates.env.from_string(msg.body).render()
    # ruleid: python.template-injection
    b = jinja2.Template("{% block x %}" + kind + "{% endblock %}").render()
    # ruleid: python.template-injection
    c = jinja2.Template(signature).render()
    form = await request.form()
    # ruleid: python.template-injection
    d = templates.env.from_string(form["footer"]).render()
    # ok: python.template-injection
    e = templates.TemplateResponse(request, "message.html", {"subject": msg.subject, "kind": kind})
    return a + b + c + d


class Settings(BaseModel):
    footer: str = "<footer>{{ year }}</footer>"


def get_settings():
    return Settings()


SettingsDep = Annotated[Settings, Depends(get_settings)]


@api.get("/footer/{year}", response_class=HTMLResponse)
async def footer(
    year: Annotated[int, Path()],
    settings: SettingsDep,
    other: Annotated[Settings, Depends(get_settings)],
    legacy: Settings = Depends(get_settings),
    title: Annotated[str, Query()] = "",
):
    # ok: python.template-injection
    a = jinja2.Template(settings.footer).render(year=year)
    # ok: python.template-injection
    b = jinja2.Template(other.footer + legacy.footer).render(year=year)
    # ok: python.template-injection
    c = jinja2.Template("<p>" + str(year) + "</p>").render()
    # ruleid: python.template-injection
    d = jinja2.Template("<title>" + title + "</title>").render()
    return a + b + c + d
