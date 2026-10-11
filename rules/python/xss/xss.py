from starlette.middleware.base import BaseHTTPMiddleware
import asyncio
import html
import json
import os
import shlex
import pathlib
import subprocess
import urllib.request
from urllib import parse
from urllib.parse import urlparse
from typing import Annotated

import bleach
import fastapi
import fastapi.responses
import markupsafe
import httpx
import nh3
import requests
from django.http import HttpResponse, HttpResponseNotFound, JsonResponse
from django.shortcuts import render
from django.template.loader import get_template, render_to_string
from django.utils.html import conditional_escape, escape as django_escape, format_html, format_html_join
from django.utils.safestring import SafeString, mark_safe
from django.views import View

from .forms import ContactForm
from .models import Article
from fastapi import Depends, FastAPI, Path, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from flask import Flask, Response, abort, jsonify, make_response, redirect, render_template, render_template_string, request, url_for
from markupsafe import Markup, escape
from pydantic import BaseModel
import starlette.responses
from starlette.responses import Response as StarletteResponse

app = Flask(__name__)
api = FastAPI()
templates = Jinja2Templates(directory="templates")

GREETINGS = {"en": "<b>Hello</b>", "fr": "<b>Bonjour</b>"}
FOOTERS = {
    # One footer per site section.
    "shop": "<footer>Shop</footer>",
    "blog": "<footer>Blog</footer>",  # the default
}
# Changed later by a view, so not an allow-list.
BANNERS = {"sale": "<em>Sale</em>"}


# Flask: a view's string return value is sent as text/html.
@app.route("/hello")
def hello():
    name = request.args.get("name", "Flask")
    # ruleid: python.xss
    return f"<p>Hello, {name}!</p>"


@app.route("/search")
def search():
    q = request.args["q"]
    # ruleid: python.xss
    return "<h1>Results for " + q + "</h1>", 200


@app.post("/comment")
def comment():
    # ruleid: python.xss
    return "<li>%s</li>" % request.form["text"]


@app.route("/agent")
def agent():
    # ruleid: python.xss
    return "<pre>{}</pre>".format(request.headers["User-Agent"])


@app.route("/theme")
def theme():
    # ruleid: python.xss
    return request.cookies.get("theme", "")


@app.post("/preview")
def preview():
    data = request.get_json()
    page = "<article>" + data["body"] + "</article>"
    # ruleid: python.xss
    return make_response(page, 200)


@app.route("/user/<username>")
def show_user(username):
    # ruleid: python.xss
    return Response("<h2>" + username + "</h2>")


@app.route("/badge")
def badge():
    # ruleid: python.xss
    label = Markup("<span>" + request.args["label"] + "</span>")
    return render_template("badge.html", label=label)


@app.route("/note")
def note():
    # ruleid: python.xss
    note_html = markupsafe.Markup(f"<p>{request.args['note']}</p>")
    return render_template("note.html", note=note_html)


# Flask: escaping, templates, JSON and constants are safe.
@app.route("/hello-safe")
def hello_safe():
    name = request.args.get("name", "Flask")
    # ok: python.xss
    return f"Hello, {escape(name)}!"


@app.route("/safe/<username>")
def safe_user(username):
    # ok: python.xss
    return "<h2>" + html.escape(username) + "</h2>"


@app.route("/greet")
def greet():
    # ok: python.xss
    return render_template("greet.html", name=request.args["name"])


@app.route("/greet-inline")
def greet_inline():
    # Request data as a context variable is escaped; data in the template itself is
    # python.template-injection.
    # ok: python.xss
    return render_template_string("<p>{{ name }}</p>", name=request.args["name"])


@app.route("/api/me")
def api_me():
    # ok: python.xss
    return jsonify(name=request.args["name"])


@app.route("/api/echo")
def api_echo():
    # ok: python.xss
    return {"echo": request.args["text"]}


@app.route("/api/list")
def api_list():
    # ok: python.xss
    return [request.args["a"], request.args["b"]]


@app.route("/count")
def count():
    # ok: python.xss
    return "<p>%d items</p>" % int(request.args["n"])


@app.route("/plain")
def plain():
    # ok: python.xss
    return Response(request.args["text"], mimetype="text/plain")


@app.route("/plain-tuple")
def plain_tuple():
    # ok: python.xss
    return request.args["text"], 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/markup-format")
def markup_format():
    # Markup's % and format() escape their arguments.
    # ok: python.xss
    label = Markup("<span>%s</span>") % request.args["label"]
    # ok: python.xss
    title = Markup("<b>{}</b>").format(request.args["title"])
    # ok: python.xss
    safe = Markup.escape(request.args["raw"])
    return render_template("label.html", label=label, title=title, safe=safe)


@app.route("/bio")
def bio():
    # ok: python.xss
    return Markup(bleach.clean(request.form["bio"]))


@app.route("/next")
def next_page():
    # Open redirects are python.open-redirect.
    # ok: python.xss
    return redirect(url_for("profile", name=request.args["name"]))


@app.route("/greeting/<lang>")
def greeting(lang):
    # ok: python.xss
    return GREETINGS.get(lang, GREETINGS["en"])


@app.route("/greeting2/<lang>")
def greeting2(lang):
    # ok: python.xss
    return GREETINGS[lang] if lang in GREETINGS else "<b>Hi</b>"


@app.route("/footer/<section>")
def section_footer(section):
    # ok: python.xss
    return FOOTERS.get(section, FOOTERS["blog"])


@app.route("/banner/<kind>")
def banner(kind):
    # ruleid: python.xss
    return BANNERS.get(kind, "")


@app.route("/greeting3/<lang>")
def greeting3(lang):
    # ruleid: python.xss
    return GREETINGS.get(lang, request.args["fallback"])


# A constant key with request data as the default.
@app.route("/greeting5")
def greeting5():
    # ruleid: python.xss
    return GREETINGS.get("de", request.args["fallback"])


# A get() with request data as its key or default makes the dict request data for the rest of
# the function, so a later lookup of a constant entry is reported.
@app.route("/greeting4/<lang>")
def greeting4(lang):
    labels = {"title": "Welcome"}
    labels.get(lang, request.args["fallback"])
    # todook: python.xss
    return labels.get("title")


@app.post("/banner")
def set_banner():
    BANNERS[request.form["kind"]] = request.form["html"]
    return "", 204


# Stored or computed data: a call's result returned whole (dicts from to_dict() become JSON), and
# an attribute of an object that a call returned (a row looked up by a request id).
@app.route("/api/posts/<slug>")
def api_post(slug):
    # ok: python.xss
    return find_post(slug).to_dict()


@app.route("/posts/<slug>")
def post_page(slug):
    post = find_post(slug)
    # ok: python.xss
    return "<h1>" + post.title + "</h1>" + find_post(slug).summary


@app.route("/drafts/<slug>")
def draft_page(slug):
    if not (draft := find_post(slug)):
        abort(404)
    # ok: python.xss
    return "<h1>" + draft.title + "</h1>"


# A slice of request data: OpenGrep does not carry taint through a slice, so the rule takes a
# slice of a request value (in place or through a variable) or of a view parameter as request
# data itself. A slice of a value built from request data is missed.
@app.route("/teaser")
def teaser():
    # ruleid: python.xss
    return "<p>" + request.args["text"][:50] + "</p>"


@app.route("/teaser-var")
def teaser_var():
    text = request.args["text"]
    # ruleid: python.xss
    return "<p>" + text[:50] + "</p>"


@app.route("/teaser-sum")
def teaser_sum():
    # todoruleid: python.xss
    return "<p>" + (request.args["a"] + request.args["b"])[:50] + "</p>"


@app.route("/teaser-escaped")
def teaser_escaped():
    text = request.args["text"]
    text = escape(text)
    # ok: python.xss
    return "<p>" + text[:50] + "</p>"


@app.route("/teaser-stripped")
def teaser_stripped():
    text = request.args["text"]
    text = text.strip()
    # todoruleid: python.xss
    return "<p>" + text[:50] + "</p>"


def find_post(slug):
    return None


# Text built around calls: concatenations that start or end with a call, string methods with
# calls in their arguments, str().
LAYOUT = "<main>{content}</main>"


def page_top():
    return "<nav></nav>"


@app.route("/layout")
def layout():
    # ruleid: python.xss
    a = make_response(page_top() + "<p>" + request.args["msg"] + "</p>" + page_top())
    # ruleid: python.xss
    b = make_response(LAYOUT.format(content=request.args.get("msg")))
    # ruleid: python.xss
    c = make_response(LAYOUT.replace("{content}", request.args.get("msg", "")))
    # ruleid: python.xss
    d = make_response(request.args["msg"].strip() + "<br>" + html.escape(request.args["sig"]))
    # ruleid: python.xss
    return str(request.args["msg"])


@app.route("/layout2")
def layout2():
    # ruleid: python.xss
    return Response(LAYOUT.format(content=request.form.get("msg")))


# The request's own JSON value returned whole is sent back as JSON.
@app.post("/api/items")
def create_item():
    item = request.get_json()
    item["id"] = 1
    # ok: python.xss
    return item, 201


@app.put("/api/items/<item_id>")
def update_item(item_id):
    payload = request.json
    # ok: python.xss
    return payload


@app.post("/api/notes")
def create_note():
    note = request.get_json()
    if "preview" in note:
        # ruleid: python.xss
        return note["preview"]
    # ok: python.xss
    return note, 201


@app.post("/api/cards")
def create_card():
    card = request.json
    card = "<div>" + card["title"] + "</div>"
    # ruleid: python.xss
    return card


@app.post("/api/echo-json")
def echo_json():
    # ok: python.xss
    return request.json


@app.post("/api/echo-json2")
def echo_json2():
    # ok: python.xss
    return request.get_json(silent=True) or {}


@app.post("/api/echo-json3")
def echo_json3():
    # ok: python.xss
    return request.json or [], 201


# The request's JSON value given a JSON default ({} or []) after it is read is still JSON.
@app.post("/api/settings")
def save_settings():
    data = request.get_json()
    data = data or {}
    # ok: python.xss
    return data


@app.post("/api/settings2")
def save_settings2():
    data = request.get_json(silent=True)
    if data is None:
        data = {}
    # ok: python.xss
    return data, 200


@app.post("/api/tags")
def save_tags():
    tags = request.json
    if not tags:
        tags = []
    # ok: python.xss
    return tags


@app.post("/api/profile")
def save_profile():
    profile = request.get_json()
    # ok: python.xss
    return profile or {}


@app.post("/api/profile2")
def save_profile2():
    profile = request.get_json(silent=True) or {}
    profile = profile or {"name": "anonymous"}
    # ok: python.xss
    return profile or {}, 201


# A default or a later value that is request text, not JSON.
@app.post("/api/fallback")
def json_fallback():
    data = request.get_json(silent=True) or request.args["text"]
    # ruleid: python.xss
    return data


@app.post("/api/fallback2")
def json_fallback2():
    data = request.get_json(silent=True)
    if not data:
        data = request.form["text"]
    # ruleid: python.xss
    return data


@app.post("/api/fallback3")
def json_fallback3():
    data = request.get_json(silent=True)
    # ruleid: python.xss
    return data or request.args["text"]


@app.post("/api/fallback4")
def json_fallback4():
    # ruleid: python.xss
    return request.json or request.args["text"]


@app.post("/api/after-default")
def json_after_default():
    data = request.get_json()
    data = data or {}
    if "title" in data:
        data = "<h1>" + data["title"] + "</h1>"
    # ruleid: python.xss
    return data


@app.post("/api/before-default")
def json_before_default():
    data = request.get_json()
    data = "<h1>" + data["title"] + "</h1>"
    data = data or {}
    # ruleid: python.xss
    return data


@app.route("/bytes")
def as_bytes():
    # ruleid: python.xss
    return Response(request.args["q"].encode("utf-8"))


@app.route("/back-link")
def back_link():
    target = parse.urlsplit(request.args["back"])
    # ruleid: python.xss
    return "<a href='" + target.path + "'>back</a>"


@app.route("/plain-headers")
def plain_headers():
    # ok: python.xss
    return request.args["text"], {"Content-Type": "text/plain"}


# Request text that was parsed or validated first is still request text.
class Comment(BaseModel):
    text: str


@app.post("/comments")
def add_comment():
    body = request.get_json()
    comment = Comment.model_validate(body)
    # ruleid: python.xss
    a = make_response("<p>" + comment.text + "</p>")
    link = urlparse(request.args["back"])
    # ruleid: python.xss
    return "<a href='" + link.path + "'>back</a>"


def django_upload(req):
    # ruleid: python.xss
    return HttpResponse("<p>Saved " + req.FILES.get("doc").name + "</p>")


# A request value that reaches an object through a variable is taken for stored data.
class Profile:
    def __init__(self, bio):
        self.bio = bio


@app.post("/profile")
def save_profile():
    raw = request.form["bio"]
    profile = Profile(raw)
    # todoruleid: python.xss
    return "<p>" + profile.bio + "</p>"


# A subscripted request value given to a constructor in place is taken for stored data.
@app.post("/profile2")
def save_profile2():
    # todoruleid: python.xss
    return "<p>" + Profile(request.form["bio"]).bio + "</p>"


# Nested tables are not recognised as allow-lists; an upper-case local is not a constant.
SECTION_FOOTERS = {"shop": {"en": "<footer>Shop</footer>"}}


@app.route("/nested/<section>")
def nested(section):
    # todook: python.xss
    a = make_response(SECTION_FOOTERS[section]["en"])
    FALLBACK = request.args["fallback"]
    # ruleid: python.xss
    return FOOTERS.get(section, FALLBACK)


# A helper's return value is not followed, even when it builds HTML from request data.
def render_card(text):
    return "<div class='card'>" + text + "</div>"


@app.route("/card")
def card():
    # todoruleid: python.xss
    return render_card(request.args["text"])


# A call's result kept in a variable and returned whole: a function of this file is followed
# (find_post returns no request data); one of another module is still taken for text.
@app.route("/api/summary/<slug>")
def api_summary(slug):
    summary = find_post(slug).to_dict()
    # ok: python.xss
    return summary


@app.route("/api/summary2/<slug>")
def api_summary2(slug):
    summary = blog_store.find_post(slug).to_dict()
    # todook: python.xss
    return summary


# A response whose content type is changed after it was made is not recognised.
@app.route("/plain-later")
def plain_later():
    # todook: python.xss
    resp = make_response(request.args["text"])
    resp.mimetype = "text/plain"
    return resp


# A membership check against an allow-list is not recognised.
@app.route("/color")
def color():
    c = request.args["c"]
    if c not in ("red", "green"):
        abort(400)
    # todook: python.xss
    return "<p style='color:" + c + "'>colour</p>"


# Flask typed converter: the rule cannot see that <int:n> is an int.
@app.route("/post/<int:post_id>")
def show_post(post_id):
    # todook: python.xss
    return f"<p>Post {post_id}</p>"


# A Flask view parameter annotated int is not a source, although Flask passes a str for a
# <name> rule without a converter.
@app.route("/legacy/<legacy_name>")
def legacy(legacy_name: int):
    # todoruleid: python.xss
    return "<p>" + legacy_name + "</p>"


# Class-based Flask views (MethodView) are not taken for views.
from flask.views import MethodView


class ItemView(MethodView):
    def get(self):
        # todoruleid: python.xss
        return "<p>" + request.args["item"] + "</p>"


# Django: HttpResponse (text/html by default), mark_safe, SafeString, format_html's format string.
def django_hello(request):
    # ruleid: python.xss
    return HttpResponse("<p>Hello " + request.GET["name"] + "</p>")


def django_tag(request, tag):
    # ruleid: python.xss
    return HttpResponseNotFound(f"<h1>No posts tagged {tag}</h1>")


def django_bio(request):
    bio = request.POST.get("bio", "")
    # ruleid: python.xss
    context = {"bio": mark_safe(bio)}
    return render(request, "profile.html", context)


def django_snippet(request):
    # ruleid: python.xss
    snippet = SafeString(json.loads(request.body)["html"])
    # ruleid: python.xss
    link = format_html(f"<a href='/u/{request.GET['u']}'>{{}}</a>", "profile")
    return render(request, "snippet.html", {"snippet": snippet, "link": link})


def django_stream(request):
    response = HttpResponse()
    # ruleid: python.xss
    response.write("<p>" + request.COOKIES["last_search"] + "</p>")
    return response


class EchoView(View):
    def get(self, request, word):
        # ruleid: python.xss
        return HttpResponse(word)

    def post(self, request):
        # ruleid: python.xss
        return HttpResponse(self.request.POST["msg"], content_type="text/html")


def django_safe(request):
    name = request.GET["name"]
    # ok: python.xss
    a = HttpResponse("<p>Hello " + django_escape(name) + "</p>")
    # ok: python.xss
    b = HttpResponse("<p>" + conditional_escape(name) + "</p>")
    # ok: python.xss
    c = format_html("<p>Hello {}</p>", name)
    # ok: python.xss
    d = format_html_join("\n", "<li>{}</li>", ((n,) for n in request.GET.getlist("n")))
    # ok: python.xss
    e = mark_safe("<b>" + escape(name) + "</b>")
    # ok: python.xss
    f = HttpResponse(json.dumps({"name": name}), content_type="application/json")
    # ok: python.xss
    g = HttpResponse(name, "text/plain")
    # ok: python.xss
    h = JsonResponse({"name": name})
    # ok: python.xss
    i = mark_safe(get_template("hello.html").render({"name": name}, request))
    template = get_template("hello.html")
    # ok: python.xss
    j = mark_safe(template.render({"name": name}, request))
    # ok: python.xss
    m = mark_safe(render_to_string("hello.html", {"name": name}))
    # ok: python.xss
    k = mark_safe(nh3.clean(request.GET["bio"]))
    # ok: python.xss
    return render(request, "hello.html", {"name": name})


def django_article(request, slug):
    article = Article.objects.get(slug=slug)
    # ok: python.xss
    return HttpResponse("<h1>" + article.title + "</h1>")


# A form built from request data: its cleaned_data is still the request's text.
def django_contact(request):
    form = ContactForm(request.POST)
    if form.is_valid():
        # ruleid: python.xss
        return HttpResponse("<p>Thanks, " + form.cleaned_data["name"] + "</p>")
    return render(request, "contact.html", {"form": form})


# path("posts/<int:pk>/", views.django_post): the converter is in urls.py.
def django_post(request, pk):
    # todook: python.xss
    return HttpResponse(f"<p>Post {pk}</p>")


# A function named like a class-based view's handler (get, post, ...) that takes (self, request,
# ...) is taken for one also outside a class: its parameters after request count as URL arguments.
def get(self, request, pk):
    # todook: python.xss
    return HttpResponse(f"<p>Post {pk}</p>")


# A default value: Django passes the URL value when the pattern captures one.
def django_page(request, page="1"):
    # todook: python.xss
    return HttpResponse("<p>Page " + page + "</p>")


# Helpers whose first parameter is named request look like views: other parameters count as URL
# arguments, and an outgoing request (an HTTP client's) has its headers taken as request data.
def render_row(request, cell):
    # todook: python.xss
    return mark_safe("<td>" + cell + "</td>")


def describe_outgoing(request):
    # todook: python.xss
    return mark_safe("<code>" + request.headers["Accept"] + "</code>")


# FastAPI: HTMLResponse, a view declared with response_class=HTMLResponse, Response with an HTML
# media type.
class Post(BaseModel):
    title: str
    body: str


@api.get("/items/{item_id}", response_class=HTMLResponse)
async def read_item(item_id: str, q: str = ""):
    # ruleid: python.xss
    return f"<h1>Item {item_id}</h1><p>{q}</p>"


@api.post("/posts")
async def create_post(post: Post):
    # ruleid: python.xss
    return HTMLResponse(content="<h1>" + post.title + "</h1>")


@api.get("/raw")
async def raw(request: Request):
    # ruleid: python.xss
    return StarletteResponse(content=request.query_params["html"], media_type="text/html")


@api.get("/safe-items/{item_id}", response_class=HTMLResponse)
async def read_item_safe(item_id: str):
    # ok: python.xss
    return f"<h1>Item {html.escape(item_id)}</h1>"


@api.get("/tpl/{item_id}", response_class=HTMLResponse)
async def read_item_template(request: Request, item_id: str):
    # ok: python.xss
    return templates.TemplateResponse(request=request, name="item.html", context={"id": item_id})


@api.get("/json/{item_id}")
async def read_item_json(item_id: str):
    # A FastAPI view returns JSON by default.
    # ok: python.xss
    return f"<h1>Item {item_id}</h1>"


@api.get("/text/{item_id}")
async def read_item_text(item_id: str):
    # ok: python.xss
    return PlainTextResponse("Item " + item_id)


@api.get("/count/{n}", response_class=HTMLResponse)
async def read_count(n: int):
    # ok: python.xss
    return f"<p>{n} items</p>"


class Settings(BaseModel):
    footer: str = "<footer>Example</footer>"


def get_settings():
    return Settings()


SettingsDep = Annotated[Settings, Depends(get_settings)]


@api.get("/page/{num}", response_class=HTMLResponse)
async def page(
    num: Annotated[int, Path()],
    settings: SettingsDep,
    other: Annotated[Settings, Depends(get_settings)],
    title: Annotated[str, Query()] = "",
):
    footer = settings.footer + other.footer
    # ruleid: python.xss
    return f"<h1>{title}</h1><p>{num}</p>" + footer


@api.get("/footer", response_class=HTMLResponse)
async def footer(settings: Settings = Depends(get_settings)):
    # ok: python.xss
    return settings.footer


# Look-alikes: a Markup or HttpResponse of another library, a non-view function.
class Report:
    def Markup(self, text):
        return text


def build_cell(text):
    # ok: python.xss
    return "<td>" + text + "</td>"


@app.route("/report")
def report():
    r = Report()
    # ok: python.xss
    r.Markup(request.args["x"])
    # ok: python.xss
    return render_template("report.html", cell=build_cell(request.args["x"]))


# Each response form with each body shape: request data as a name, str() of it and a listed string
# method are text; a call such as parse.quote() and another method (isdigit()) are not.
@app.route("/forms/flask")
def response_forms_flask():
    q = request.args["q"]
    # ruleid: python.xss
    f0_0 = make_response(q)
    # ruleid: python.xss
    f0_1 = make_response(str(q))
    # ruleid: python.xss
    f0_2 = make_response(q.upper())
    # ok: python.xss
    f0_3 = make_response(parse.quote(q))
    # ok: python.xss
    f0_4 = make_response(q.isdigit())
    # ruleid: python.xss
    f1_0 = Response(q)
    # ruleid: python.xss
    f1_1 = Response(str(q))
    # ruleid: python.xss
    f1_2 = Response(q.upper())
    # ok: python.xss
    f1_3 = Response(parse.quote(q))
    # ok: python.xss
    f1_4 = Response(q.isdigit())
    # ruleid: python.xss
    f2_0 = Response(response=q)
    # ruleid: python.xss
    f2_1 = Response(response=str(q))
    # ruleid: python.xss
    f2_2 = Response(response=q.upper())
    # ok: python.xss
    f2_3 = Response(response=parse.quote(q))
    # ok: python.xss
    f2_4 = Response(response=q.isdigit())
    # A content type other than HTML.
    # ok: python.xss
    f3 = Response(q, content_type="text/plain; charset=utf-8")
    return "ok"


@api.get("/forms/fastapi")
def response_forms_fastapi(q: str):
    # ruleid: python.xss
    a0_0 = HTMLResponse(q)
    # ruleid: python.xss
    a0_1 = HTMLResponse(str(q))
    # ruleid: python.xss
    a0_2 = HTMLResponse(q.upper())
    # ok: python.xss
    a0_3 = HTMLResponse(parse.quote(q))
    # ok: python.xss
    a0_4 = HTMLResponse(q.isdigit())
    # ruleid: python.xss
    a1_0 = HTMLResponse(content=q)
    # ruleid: python.xss
    a1_1 = HTMLResponse(content=str(q))
    # ruleid: python.xss
    a1_2 = HTMLResponse(content=q.upper())
    # ok: python.xss
    a1_3 = HTMLResponse(content=parse.quote(q))
    # ok: python.xss
    a1_4 = HTMLResponse(content=q.isdigit())
    # ruleid: python.xss
    a2_0 = starlette.responses.HTMLResponse(q)
    # ruleid: python.xss
    a2_1 = starlette.responses.HTMLResponse(str(q))
    # ruleid: python.xss
    a2_2 = starlette.responses.HTMLResponse(q.upper())
    # ok: python.xss
    a2_3 = starlette.responses.HTMLResponse(parse.quote(q))
    # ok: python.xss
    a2_4 = starlette.responses.HTMLResponse(q.isdigit())
    # ruleid: python.xss
    a3_0 = starlette.responses.HTMLResponse(content=q)
    # ruleid: python.xss
    a3_1 = starlette.responses.HTMLResponse(content=str(q))
    # ruleid: python.xss
    a3_2 = starlette.responses.HTMLResponse(content=q.upper())
    # ok: python.xss
    a3_3 = starlette.responses.HTMLResponse(content=parse.quote(q))
    # ok: python.xss
    a3_4 = starlette.responses.HTMLResponse(content=q.isdigit())
    # ruleid: python.xss
    a4_0 = fastapi.Response(q, media_type="text/html")
    # ruleid: python.xss
    a4_1 = fastapi.Response(str(q), media_type="text/html")
    # ruleid: python.xss
    a4_2 = fastapi.Response(q.upper(), media_type="text/html")
    # ok: python.xss
    a4_3 = fastapi.Response(parse.quote(q), media_type="text/html")
    # ok: python.xss
    a4_4 = fastapi.Response(q.isdigit(), media_type="text/html")
    # ruleid: python.xss
    a5_0 = fastapi.Response(content=q, media_type="text/html")
    # ruleid: python.xss
    a5_1 = fastapi.Response(content=str(q), media_type="text/html")
    # ruleid: python.xss
    a5_2 = fastapi.Response(content=q.upper(), media_type="text/html")
    # ok: python.xss
    a5_3 = fastapi.Response(content=parse.quote(q), media_type="text/html")
    # ok: python.xss
    a5_4 = fastapi.Response(content=q.isdigit(), media_type="text/html")
    # ruleid: python.xss
    a6_0 = fastapi.responses.Response(q, media_type="text/html")
    # ruleid: python.xss
    a6_1 = fastapi.responses.Response(str(q), media_type="text/html")
    # ruleid: python.xss
    a6_2 = fastapi.responses.Response(q.upper(), media_type="text/html")
    # ok: python.xss
    a6_3 = fastapi.responses.Response(parse.quote(q), media_type="text/html")
    # ok: python.xss
    a6_4 = fastapi.responses.Response(q.isdigit(), media_type="text/html")
    # ruleid: python.xss
    a7_0 = fastapi.responses.Response(content=q, media_type="text/html")
    # ruleid: python.xss
    a7_1 = fastapi.responses.Response(content=str(q), media_type="text/html")
    # ruleid: python.xss
    a7_2 = fastapi.responses.Response(content=q.upper(), media_type="text/html")
    # ok: python.xss
    a7_3 = fastapi.responses.Response(content=parse.quote(q), media_type="text/html")
    # ok: python.xss
    a7_4 = fastapi.responses.Response(content=q.isdigit(), media_type="text/html")
    # ruleid: python.xss
    a8_0 = StarletteResponse(q, media_type="text/html")
    # ruleid: python.xss
    a8_1 = StarletteResponse(str(q), media_type="text/html")
    # ruleid: python.xss
    a8_2 = StarletteResponse(q.upper(), media_type="text/html")
    # ok: python.xss
    a8_3 = StarletteResponse(parse.quote(q), media_type="text/html")
    # ok: python.xss
    a8_4 = StarletteResponse(q.isdigit(), media_type="text/html")
    # ruleid: python.xss
    a9_0 = StarletteResponse(content=q, media_type="text/html")
    # ruleid: python.xss
    a9_1 = StarletteResponse(content=str(q), media_type="text/html")
    # ruleid: python.xss
    a9_2 = StarletteResponse(content=q.upper(), media_type="text/html")
    # ok: python.xss
    a9_3 = StarletteResponse(content=parse.quote(q), media_type="text/html")
    # ok: python.xss
    a9_4 = StarletteResponse(content=q.isdigit(), media_type="text/html")
    return {"ok": True}


def response_forms_django(request):
    q = request.GET["q"]
    resp = HttpResponse()
    # ruleid: python.xss
    d0_0 = HttpResponse(q)
    # ruleid: python.xss
    d0_1 = HttpResponse(str(q))
    # ruleid: python.xss
    d0_2 = HttpResponse(q.upper())
    # ok: python.xss
    d0_3 = HttpResponse(parse.quote(q))
    # ok: python.xss
    d0_4 = HttpResponse(q.isdigit())
    # ruleid: python.xss
    d1_0 = HttpResponse(content=q)
    # ruleid: python.xss
    d1_1 = HttpResponse(content=str(q))
    # ruleid: python.xss
    d1_2 = HttpResponse(content=q.upper())
    # ok: python.xss
    d1_3 = HttpResponse(content=parse.quote(q))
    # ok: python.xss
    d1_4 = HttpResponse(content=q.isdigit())
    # ruleid: python.xss
    d2_0 = resp.write(q)
    # ruleid: python.xss
    d2_1 = resp.write(str(q))
    # ruleid: python.xss
    d2_2 = resp.write(q.upper())
    # ok: python.xss
    d2_3 = resp.write(parse.quote(q))
    # ok: python.xss
    d2_4 = resp.write(q.isdigit())
    # A content type other than HTML, and write() on an object that is not a response.
    # ok: python.xss
    d3 = HttpResponse(q, content_type="text/csv")
    text = HttpResponse(content_type="text/plain")
    # ok: python.xss
    text.write(q)
    log = make_log()
    # ok: python.xss
    log.write(q)
    return resp

# Flask view returns: the body alone and the tuple forms, with each body shape; the request's
# own JSON value returned whole; a response kept in a variable; other decorators.


@app.route("/returns/0")
def flask_return_0():
    q = request.args["q"]
    # ruleid: python.xss
    return q, 200


@app.route("/returns/1")
def flask_return_1():
    q = request.args["q"]
    # ruleid: python.xss
    return q, 200, {"X-Frame-Options": "DENY"}


@app.route("/returns/2")
def flask_return_2():
    q = request.args["q"]
    # ruleid: python.xss
    return str(q), 200


@app.route("/returns/3")
def flask_return_3():
    q = request.args["q"]
    # ruleid: python.xss
    return str(q), 200, {"X-Frame-Options": "DENY"}


@app.route("/returns/4")
def flask_return_4():
    q = request.args["q"]
    # ruleid: python.xss
    return q.upper(), 200


@app.route("/returns/5")
def flask_return_5():
    q = request.args["q"]
    # ruleid: python.xss
    return q.upper(), 200, {"X-Frame-Options": "DENY"}


@app.route("/returns/6")
def flask_return_6():
    q = request.args["q"]
    # ok: python.xss
    return parse.quote(q), 200


@app.route("/returns/7")
def flask_return_7():
    q = request.args["q"]
    # ok: python.xss
    return parse.quote(q), 200, {"X-Frame-Options": "DENY"}


@app.route("/returns/8")
def flask_return_8():
    q = request.args["q"]
    # ok: python.xss
    return q.isdigit(), 200


@app.route("/returns/9")
def flask_return_9():
    q = request.args["q"]
    # ok: python.xss
    return q.isdigit(), 200, {"X-Frame-Options": "DENY"}


@app.route("/returns/10")
def flask_return_10():
    q = request.args["q"]
    # ok: python.xss
    return [q], 201


@app.route("/returns/dict")
def flask_return_dict():
    q = request.args["q"]
    # ok: python.xss
    return {"q": q}, 201


@app.route("/returns/11")
def flask_return_11():
    request.args["q"]
    # ok: python.xss
    return request.get_json()


@app.route("/returns/12")
def flask_return_12():
    request.args["q"]
    # ok: python.xss
    return request.json or {}


@app.route("/returns/13")
def flask_return_13():
    request.args["q"]
    # ok: python.xss
    return request.json or []


@app.route("/returns/14")
def flask_return_14():
    request.args["q"]
    # ok: python.xss
    return request.get_json() or {}


@app.route("/returns/15")
def flask_return_15():
    request.args["q"]
    # ok: python.xss
    return request.get_json() or []


@app.route("/returns/16")
def flask_return_16():
    request.args["q"]
    # ok: python.xss
    return request.json, 201


@app.route("/returns/17")
def flask_return_17():
    request.args["q"]
    # ok: python.xss
    return request.get_json(), 201


@app.route("/returns/18")
def flask_return_18():
    request.args["q"]
    # ok: python.xss
    return request.json or {}, 201


@app.route("/returns/19")
def flask_return_19():
    request.args["q"]
    # ok: python.xss
    return request.json or [], 201


@app.route("/returns/20")
def flask_return_20():
    request.args["q"]
    # ok: python.xss
    return request.get_json() or {}, 201


@app.route("/returns/21")
def flask_return_21():
    request.args["q"]
    # ok: python.xss
    return request.get_json() or [], 201


@app.route("/returns/22")
def flask_return_22():
    q = request.args["q"]
    resp = Response(parse.quote(q))
    resp.headers["X-Frame-Options"] = "DENY"
    # ok: python.xss
    return resp


# Not a view: a template filter (its value goes through the template's autoescaping) and a
# FastAPI router's path operation (its return value is sent as JSON).
@app.template_filter("shout")
def shout_filter(text):
    # ok: python.xss
    return text.upper() + request.args["mark"]


router = fastapi.APIRouter()


@router.get("/router-echo")
def router_echo(q: str):
    # ok: python.xss
    return "<p>" + q + "</p>"


# Middleware runs for every request and is not a view: a Starlette BaseHTTPMiddleware's
# dispatch() and a FastAPI @app.middleware("http") function.
class NoticeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, incoming, call_next):
        # ruleid: python.xss
        HTMLResponse("<p>" + incoming.query_params["q"] + "</p>")
        # ruleid: python.xss
        HTMLResponse("<p>" + incoming.path_params["item"] + "</p>")
        # ruleid: python.xss
        HTMLResponse("<p>" + incoming.headers["X-Value"] + "</p>")
        # ruleid: python.xss
        HTMLResponse("<p>" + incoming.cookies["value"] + "</p>")
        # ruleid: python.xss
        HTMLResponse("<p>" + incoming.url.query + "</p>")
        # ruleid: python.xss
        HTMLResponse("<p>" + str(incoming.url) + "</p>")
        # ruleid: python.xss
        HTMLResponse("<p>" + f"{incoming.url}" + "</p>")
        # ruleid: python.xss
        HTMLResponse("<p>" + incoming.url.hostname + "</p>")
        # ruleid: python.xss
        HTMLResponse("<p>" + (await incoming.body()).decode() + "</p>")
        # The scheme is http or https; the port is a number.
        # ok: python.xss
        HTMLResponse("<p>" + incoming.url.scheme + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + str(incoming.url.port) + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + str(incoming.url.is_secure) + "</p>")
        return await call_next(incoming)


@api.middleware("http")
async def notice_middleware(incoming, call_next):
    # ruleid: python.xss
    HTMLResponse("<p>" + incoming.url.path + "</p>")
    # ruleid: python.xss
    HTMLResponse("<p>" + incoming.url.path[1:] + "</p>")
    # ruleid: python.xss
    HTMLResponse("<p>" + incoming.url.path[:64] + "</p>")
    # ruleid: python.xss
    HTMLResponse("<p>" + incoming.url.path[1:64] + "</p>")
    # ruleid: python.xss
    HTMLResponse("<p>" + (await incoming.json())["value"] + "</p>")
    # ruleid: python.xss
    HTMLResponse("<p>" + (await incoming.form())["value"] + "</p>")
    async for chunk in incoming.stream():
        # ruleid: python.xss
        HTMLResponse("<p>" + chunk.decode() + "</p>")
    # A slice of a middleware value other than the path, in place or through a variable, is
    # missed.
    # todoruleid: python.xss
    HTMLResponse("<p>" + incoming.query_params["q"][:40] + "</p>")
    return await call_next(incoming)


# Not middleware: a dispatch() method of a class that is not a BaseHTTPMiddleware.
class NoticeRouter:
    async def dispatch(self, incoming, call_next):
        # ok: python.xss
        HTMLResponse("<p>" + incoming.query_params["q"] + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + incoming.url.path + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + incoming.url.query + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + str(incoming.url) + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + incoming.url.hostname + "</p>")
        async for chunk in incoming.stream():
            # ok: python.xss
            HTMLResponse("<p>" + chunk.decode() + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + incoming.path_params["item"] + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + incoming.headers["X-Value"] + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + incoming.cookies["value"] + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + (await incoming.json())["value"] + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + (await incoming.body()).decode() + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + (await incoming.form())["value"] + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + incoming.url.path[1:] + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + incoming.url.path[:64] + "</p>")
        # ok: python.xss
        HTMLResponse("<p>" + incoming.url.path[1:64] + "</p>")


# A Flask before_request hook reads flask.request.
@app.before_request
def notice_hook():
    # ruleid: python.xss
    HTMLResponse("<p>" + request.args["q"] + "</p>")


# The results of other rules' sinks (a decision, as in js.xss, java.xss and go.xss): what a command
# prints when request data chose the command (its shell command, its program, the script of a
# shell, cmd.exe or PowerShell) is python.command-injection's finding, and the content of a file
# the request named is python.path-traversal's: neither is reported again here. A fixed program
# given request data as an argument can print it back, so its output stays request data, and so
# does a page fetched from a URL the request chooses (ruling J2); one fetched from a fixed origin
# is that service's data.
PAGES = "/srv/pages"
API_BASE = "https://api.example.com"


@app.route("/results/shell")
def results_shell():
    listing = subprocess.check_output("ls -l " + request.args["dir"], shell=True)
    # ok: python.xss
    return listing


@app.route("/results/shell-inline")
def results_shell_inline():
    # ok: python.xss
    return subprocess.check_output(f"du -sh {request.args['dir']}", shell=True).decode()


@app.route("/results/popen")
def results_popen():
    found = os.popen("grep -r " + request.args["word"] + " /srv/docs").read()
    # ok: python.xss
    return "<pre>" + found + "</pre>"


@app.route("/results/getoutput")
def results_getoutput():
    status = subprocess.getoutput("systemctl status " + request.args["unit"])
    # ok: python.xss
    return "<pre>" + status + "</pre>"


@app.route("/results/program")
def results_program():
    version = subprocess.check_output([request.args["tool"], "--version"], text=True)
    # ok: python.xss
    return "<p>" + version + "</p>"


@app.route("/results/program-string")
def results_program_string():
    version = subprocess.check_output(request.args["tool"], text=True)
    # ok: python.xss
    return "<p>" + version + "</p>"


@app.route("/results/sh-c")
def results_sh_c():
    found = subprocess.check_output(["sh", "-c", "grep " + request.args["word"] + " notes.txt"], text=True)
    # ok: python.xss
    return "<pre>" + found + "</pre>"


@app.route("/results/run-shell")
def results_run_shell():
    done = subprocess.run("ping -c 1 " + request.args["host"], shell=True, capture_output=True, text=True)
    report = done.stdout
    # ok: python.xss
    return "<pre>" + report + "</pre>"


@app.route("/results/popen-shell")
def results_popen_shell():
    proc = subprocess.Popen("whois " + request.args["domain"], shell=True, stdout=subprocess.PIPE, text=True)
    out, _ = proc.communicate()
    # ok: python.xss
    return "<pre>" + out + "</pre>"


@app.route("/results/pwsh")
def results_pwsh():
    out = subprocess.check_output(["pwsh", "-NoProfile", "-Command", "Get-Service " + request.args["name"]], text=True)
    # ok: python.xss
    return "<pre>" + out + "</pre>"


@app.route("/results/cmd-list")
def results_cmd_list():
    argv = ["cmd.exe", "/c", "dir " + request.args["dir"]]
    out = subprocess.check_output(argv, text=True)
    # ok: python.xss
    return "<pre>" + out + "</pre>"


@app.route("/results/echo")
def results_echo():
    out = subprocess.check_output(["echo", request.args["msg"]], text=True)
    # ruleid: python.xss
    return "<p>" + out + "</p>"


@app.route("/results/echo-run")
def results_echo_run():
    done = subprocess.run(["figlet", request.args["msg"]], capture_output=True, text=True)
    # ruleid: python.xss
    return "<pre>" + done.stdout + "</pre>"


@app.route("/results/echo-popen")
def results_echo_popen():
    proc = subprocess.Popen(["cowsay", request.args["msg"]], stdout=subprocess.PIPE, text=True)
    out, _ = proc.communicate()
    # ruleid: python.xss
    return "<pre>" + out + "</pre>"


@app.route("/results/sh-positional")
def results_sh_positional():
    # The command is fixed; the request value is the shell's $1, which it prints back.
    out = subprocess.check_output(["sh", "-c", 'echo "Hello $1"', "sh", request.args["name"]], text=True)
    # ruleid: python.xss
    return "<p>" + out + "</p>"


@app.route("/results/file")
def results_file():
    content = open(os.path.join(PAGES, request.args["page"])).read()
    # ok: python.xss
    return content


@app.route("/results/file-with")
def results_file_with():
    with open(os.path.join(PAGES, request.args["page"]), encoding="utf-8") as page:
        body = page.read()
    # ok: python.xss
    return body


@app.route("/results/file-lines/<name>")
def results_file_lines(name):
    page = open(os.path.join(PAGES, name))
    lines = page.readlines()
    # ok: python.xss
    return "<br>".join(lines)


@app.route("/results/path/<name>")
def results_path(name):
    body = pathlib.Path(PAGES, name).read_text()
    # ok: python.xss
    return body


@app.route("/results/path-join/<name>")
def results_path_join(name):
    target = pathlib.Path(PAGES) / name
    # ok: python.xss
    return target.read_text().strip()


@app.route("/results/path-bytes/<name>")
def results_path_bytes(name):
    # ok: python.xss
    return Response((pathlib.Path(PAGES) / name).read_bytes(), mimetype="text/html")


@app.route("/results/file-name")
def results_file_name():
    # The file object still names the file the request chose.
    page = open(os.path.join(PAGES, request.args["page"]))
    # ruleid: python.xss
    return "<p>Opened " + page.name + "</p>"


@app.route("/results/path-name/<name>")
def results_path_name(name):
    # ruleid: python.xss
    return "<p>Opened " + pathlib.Path(PAGES, name).name + "</p>"


@app.route("/results/fetch-url")
def results_fetch_url():
    reply = urllib.request.urlopen(request.args["url"])
    # ruleid: python.xss
    return "<p>Fetched " + reply.url + "</p>"


@app.route("/results/file-iter")
def results_file_iter():
    # Iterating over the file (or reading it through a helper) is not recognised as reading it.
    rows = []
    with open(os.path.join(PAGES, request.args["page"])) as page:
        for line in page:
            rows.append(line)
    # todook: python.xss
    return "".join(rows)


@app.route("/results/fetch")
def results_fetch():
    reply = requests.get(request.args["url"])
    # ruleid: python.xss
    return reply.text


@app.route("/results/fetch-inline")
def results_fetch_inline():
    page = requests.get(request.args["url"], timeout=5).text
    # ruleid: python.xss
    return page


@app.route("/results/fetch-urlopen")
def results_fetch_urlopen():
    page = urllib.request.urlopen(request.args["url"]).read()
    # ruleid: python.xss
    return page


@app.route("/results/fetch-httpx")
def results_fetch_httpx():
    page = httpx.get(request.args["url"]).text
    # ruleid: python.xss
    return page


@app.route("/results/fetch-scheme")
def results_fetch_scheme():
    # A lone scheme fixes no host.
    page = requests.get("https://" + request.args["host"] + "/status").text
    # ruleid: python.xss
    return page


@app.route("/results/fetch-no-separator")
def results_fetch_no_separator():
    # Without a separator after the host, "@evil.example" in the path sets the host.
    page = requests.get("https://api.example.com" + request.args["path"]).text
    # ruleid: python.xss
    return page


@app.route("/results/fetch-session-inline")
def results_fetch_session_inline():
    page = requests.Session().post(request.args["url"]).content
    # ruleid: python.xss
    return page


@app.route("/results/fetch-session-inline-get")
def results_fetch_session_inline_get():
    # get() on a call's result: the dict.get() propagator gives the key's request data to the
    # receiver, which is no variable here, so it is lost.
    page = requests.Session().get(request.args["url"]).content
    # todoruleid: python.xss
    return page


@app.route("/results/fetch-fixed")
def results_fetch_fixed():
    page = requests.get("https://api.example.com/items/" + request.args["id"]).text
    # ok: python.xss
    return page


@app.route("/results/fetch-fixed-fstring")
def results_fetch_fixed_fstring():
    item = requests.get(f"https://api.example.com/items/{request.args['id']}", timeout=5).json()
    # ok: python.xss
    return "<h1>" + item["title"] + "</h1>"


@app.route("/results/fetch-fixed-query")
def results_fetch_fixed_query():
    feed = urllib.request.urlopen("https://feeds.example.com?q=" + request.args["q"]).read()
    # ok: python.xss
    return feed


@app.route("/results/fetch-fixed-keyword")
def results_fetch_fixed_keyword():
    page = httpx.request("GET", url="https://api.example.com/pages/" + request.args["id"]).text
    # ok: python.xss
    return page


@app.route("/results/fetch-session")
def results_fetch_session():
    # A Session held in a variable: the attribute of its result is taken for stored data.
    session = requests.Session()
    page = session.get(request.args["url"]).text
    # todoruleid: python.xss
    return page


@app.route("/results/fetch-constant-base")
def results_fetch_constant_base():
    # An origin held in a module constant is not recognised.
    page = requests.get(API_BASE + "/items/" + request.args["id"]).json()
    # todook: python.xss
    return "<h1>" + page["title"] + "</h1>"


# Every form of the file and fetch results above, as a page body.
@app.route("/results/more/<name>")
def results_more(name):
    first = open(os.path.join(PAGES, name)).readline()
    # ok: python.xss
    make_response(first)
    every = open(os.path.join(PAGES, name)).readlines()
    # ok: python.xss
    make_response("".join(every))
    with open(os.path.join(PAGES, name)) as page:
        title = page.readline()
    # ok: python.xss
    make_response(title)
    raw = pathlib.Path(PAGES, name).read_bytes()
    # ok: python.xss
    make_response(raw)
    joined = (pathlib.Path(PAGES) / name).read_text()
    # ok: python.xss
    make_response(joined)
    joined_raw = (pathlib.Path(PAGES) / name).read_bytes()
    # ok: python.xss
    make_response(joined_raw)
    target = pathlib.Path(PAGES, name)
    text = target.read_text()
    # ok: python.xss
    make_response(text)
    data = target.read_bytes()
    # ok: python.xss
    make_response(data)
    return "done"


@app.route("/results/more-fetch/<item>")
def results_more_fetch(item):
    a = requests.post(url="https://api.example.com/render/" + item).text
    # ok: python.xss
    make_response(a)
    b = httpx.get("https://api.example.com/items/" + item).text
    # ok: python.xss
    make_response(b)
    c = httpx.post(url="https://api.example.com/render?item=" + item).text
    # ok: python.xss
    make_response(c)
    d = requests.request("GET", "https://api.example.com/items/" + item).text
    # ok: python.xss
    make_response(d)
    e = requests.request(method="GET", url="https://api.example.com/items/" + item).text
    # ok: python.xss
    make_response(e)
    f = httpx.request("GET", f"https://api.example.com/items/{item}").text
    # ok: python.xss
    make_response(f)
    with httpx.stream("GET", "https://api.example.com/items/" + item) as streamed:
        g = streamed.read()
    # ok: python.xss
    make_response(g)
    with httpx.stream(method="GET", url="https://api.example.com/items/" + item) as streamed:
        h = streamed.read()
    # ok: python.xss
    make_response(h)
    i = urllib.request.urlopen(url="https://api.example.com/items/" + item).read()
    # ok: python.xss
    make_response(i)
    j = httpx.get(item).text
    # ruleid: python.xss
    make_response(j)
    return "done"


class Collect(asyncio.SubprocessProtocol):
    pass


class Job(BaseModel):
    argv: list[str]
    line: str


# Every command position python.command-injection reports, whose output is therefore not
# reported here (the sanitizers copied from that rule).
@app.route("/results/commands/<arg>")
async def results_commands(arg):
    q = request.args["q"]
    status = os.system("ping -c 1 " + q)
    # ok: python.xss
    make_response(status)
    pair = subprocess.getstatusoutput("ls " + q)
    # ok: python.xss
    make_response(pair)
    proc = await asyncio.create_subprocess_shell("ls " + q, stdout=asyncio.subprocess.PIPE)
    shell_out, _ = await proc.communicate()
    # ok: python.xss
    make_response(shell_out)
    running = await asyncio.get_running_loop().subprocess_shell(Collect, "ls " + q)
    # ok: python.xss
    make_response(running)
    current = await asyncio.get_event_loop().subprocess_shell(Collect, "ls " + q)
    # ok: python.xss
    make_response(current)
    loop = asyncio.get_running_loop()
    looped = await loop.subprocess_shell(Collect, "ls " + q)
    # ok: python.xss
    make_response(looped)
    keyword = subprocess.check_output(args="ls " + q, shell=True)
    # ok: python.xss
    make_response(keyword)
    keyword_last = subprocess.check_output(shell=True, args="ls " + q)
    # ok: python.xss
    make_response(keyword_last)
    program_tuple = subprocess.check_output((q, "--version"))
    # ok: python.xss
    make_response(program_tuple)
    program_plus = subprocess.check_output([q] + ["--version"])
    # ok: python.xss
    make_response(program_plus)
    program_args = subprocess.check_output(args=[q, "--version"])
    # ok: python.xss
    make_response(program_args)
    program_args_tuple = subprocess.check_output(args=(q, "--version"))
    # ok: python.xss
    make_response(program_args_tuple)
    replaced = subprocess.check_output(["tool", "--version"], executable=q)
    # ok: python.xss
    make_response(replaced)
    exec_proc = await asyncio.create_subprocess_exec(q, "--version", stdout=asyncio.subprocess.PIPE)
    exec_out, _ = await exec_proc.communicate()
    # ok: python.xss
    make_response(exec_out)
    exec_running = await asyncio.get_running_loop().subprocess_exec(Collect, q)
    # ok: python.xss
    make_response(exec_running)
    exec_current = await asyncio.get_event_loop().subprocess_exec(Collect, q)
    # ok: python.xss
    make_response(exec_current)
    event_loop = asyncio.get_event_loop()
    exec_looped = await event_loop.subprocess_exec(Collect, q)
    # ok: python.xss
    make_response(exec_looped)
    shell_looped = await event_loop.subprocess_shell(Collect, "ls " + q)
    # ok: python.xss
    make_response(shell_looped)
    return "done"


# os.exec*(), os.spawn*() and os.posix_spawn*() return no output (an exit status or a process id,
# or they never return); their program is still that rule's finding.
@app.route("/results/spawn")
def results_spawn():
    q = request.args["q"]
    a = os.execl(q, "tool")
    # ok: python.xss
    make_response(a)
    b = os.execle(q, "tool", {})
    # ok: python.xss
    make_response(b)
    c = os.execlp(q, "tool")
    # ok: python.xss
    make_response(c)
    d = os.execlpe(q, "tool", {})
    # ok: python.xss
    make_response(d)
    e = os.execv(q, ["tool"])
    # ok: python.xss
    make_response(e)
    f = os.execve(q, ["tool"], {})
    # ok: python.xss
    make_response(f)
    g = os.execvp(q, ["tool"])
    # ok: python.xss
    make_response(g)
    h = os.execvpe(q, ["tool"], {})
    # ok: python.xss
    make_response(h)
    i = os.spawnl(os.P_WAIT, q, "tool")
    # ok: python.xss
    make_response(i)
    j = os.spawnle(os.P_WAIT, q, "tool", {})
    # ok: python.xss
    make_response(j)
    k = os.spawnlp(os.P_WAIT, q, "tool")
    # ok: python.xss
    make_response(k)
    m = os.spawnlpe(os.P_WAIT, q, "tool", {})
    # ok: python.xss
    make_response(m)
    n = os.spawnv(os.P_WAIT, q, ["tool"])
    # ok: python.xss
    make_response(n)
    o = os.spawnve(os.P_WAIT, q, ["tool"], {})
    # ok: python.xss
    make_response(o)
    p = os.spawnvp(os.P_WAIT, q, ["tool"])
    # ok: python.xss
    make_response(p)
    r = os.spawnvpe(os.P_WAIT, q, ["tool"], {})
    # ok: python.xss
    make_response(r)
    s = os.posix_spawn(q, ["tool"], {})
    # ok: python.xss
    make_response(s)
    t = os.posix_spawnp(q, ["tool"], {})
    # ok: python.xss
    make_response(t)
    return "done"


# Argument lists: a request-chosen program in a list held in a variable, and the command of a
# POSIX shell after -c (after up to three option words), in place and held in a variable.
@app.route("/results/shells")
async def results_shells():
    q = request.args["q"]
    held = [q, "--version"]
    # ok: python.xss
    make_response(subprocess.check_output(held).decode())
    held_tuple = (q, "--version")
    # ok: python.xss
    make_response(subprocess.check_output(held_tuple).decode())
    a = subprocess.check_output(("sh", "-c", "ls " + q))
    # ok: python.xss
    make_response(a)
    b = subprocess.check_output(args=["sh", "-c", "ls " + q])
    # ok: python.xss
    make_response(b)
    proc = await asyncio.create_subprocess_exec("sh", "-c", "ls " + q, stdout=asyncio.subprocess.PIPE)
    c, _ = await proc.communicate()
    # ok: python.xss
    make_response(c)
    d = subprocess.check_output(["bash", "-e", "-c", "ls " + q])
    # ok: python.xss
    make_response(d)
    e = subprocess.check_output(("bash", "-e", "-c", "ls " + q))
    # ok: python.xss
    make_response(e)
    f = subprocess.check_output(args=["bash", "-e", "-c", "ls " + q])
    # ok: python.xss
    make_response(f)
    proc = await asyncio.create_subprocess_exec("bash", "-e", "-c", "ls " + q, stdout=asyncio.subprocess.PIPE)
    g, _ = await proc.communicate()
    # ok: python.xss
    make_response(g)
    h = subprocess.check_output(["bash", "-e", "-u", "-c", "ls " + q])
    # ok: python.xss
    make_response(h)
    i = subprocess.check_output(("bash", "-e", "-u", "-c", "ls " + q))
    # ok: python.xss
    make_response(i)
    j = subprocess.check_output(args=["bash", "-e", "-u", "-c", "ls " + q])
    # ok: python.xss
    make_response(j)
    proc = await asyncio.create_subprocess_exec("bash", "-e", "-u", "-c", "ls " + q, stdout=asyncio.subprocess.PIPE)
    k, _ = await proc.communicate()
    # ok: python.xss
    make_response(k)
    m = subprocess.check_output(["bash", "-e", "-u", "-x", "-c", "ls " + q])
    # ok: python.xss
    make_response(m)
    n = subprocess.check_output(("bash", "-e", "-u", "-x", "-c", "ls " + q))
    # ok: python.xss
    make_response(n)
    o = subprocess.check_output(args=["bash", "-e", "-u", "-x", "-c", "ls " + q])
    # ok: python.xss
    make_response(o)
    proc = await asyncio.create_subprocess_exec("bash", "-e", "-u", "-x", "-c", "ls " + q, stdout=asyncio.subprocess.PIPE)
    p, _ = await proc.communicate()
    # ok: python.xss
    make_response(p)
    argv0 = ["sh", "-c", "ls " + q]
    # ok: python.xss
    make_response(subprocess.check_output(argv0).decode())
    argv1 = ["bash", "-e", "-c", "ls " + q]
    # ok: python.xss
    make_response(subprocess.check_output(argv1).decode())
    argv2 = ["bash", "-e", "-u", "-c", "ls " + q]
    # ok: python.xss
    make_response(subprocess.check_output(argv2).decode())
    argv3 = ["bash", "-e", "-u", "-x", "-c", "ls " + q]
    # ok: python.xss
    make_response(subprocess.check_output(argv3).decode())
    return "done"


# cmd.exe after /c or /k, and PowerShell's command, script and first positional argument, in a
# list or tuple written in the call, given as args=, to asyncio's exec, or held in a variable.
@app.route("/results/windows")
async def results_windows():
    q = request.args["q"]
    a = subprocess.check_output(["cmd", "/c", "dir " + q])
    # ok: python.xss
    make_response(a)
    b = subprocess.check_output(("cmd.exe", "/k", "dir " + q))
    # ok: python.xss
    make_response(b)
    c = subprocess.check_output(args=["cmd", "/c", "dir " + q])
    # ok: python.xss
    make_response(c)
    d = subprocess.check_output(("pwsh", "-Command", "Get-Item " + q))
    # ok: python.xss
    make_response(d)
    e = subprocess.check_output(["pwsh", "-cwa", "Get-Item " + q])
    # ok: python.xss
    make_response(e)
    f = subprocess.check_output(("powershell.exe", "-EncodedCommand", q))
    # ok: python.xss
    make_response(f)
    g = subprocess.check_output(["pwsh", q])
    # ok: python.xss
    make_response(g)
    h = subprocess.check_output(("pwsh", q))
    # ok: python.xss
    make_response(h)
    i = subprocess.check_output(["pwsh", "-NoProfile", q])
    # ok: python.xss
    make_response(i)
    j = subprocess.check_output(("pwsh", "-NoProfile", q))
    # ok: python.xss
    make_response(j)
    k = subprocess.check_output(["pwsh", "-ExecutionPolicy", "Bypass", q])
    # ok: python.xss
    make_response(k)
    m = subprocess.check_output(("pwsh", "-ExecutionPolicy", "Bypass", q))
    # ok: python.xss
    make_response(m)
    n = subprocess.check_output(["powershell.exe", "-Version", "5.1", q])
    # ok: python.xss
    make_response(n)
    o = subprocess.check_output(("powershell.exe", "-Version", "5.1", q))
    # ok: python.xss
    make_response(o)
    p = subprocess.check_output(["powershell.exe", "Get-Item", q])
    # ok: python.xss
    make_response(p)
    r = subprocess.check_output(("powershell.exe", "Get-Item", q))
    # ok: python.xss
    make_response(r)
    proc = await asyncio.create_subprocess_exec("cmd", "/c", "dir " + q, stdout=asyncio.subprocess.PIPE)
    s, _ = await proc.communicate()
    # ok: python.xss
    make_response(s)
    proc = await asyncio.create_subprocess_exec("pwsh", "-Command", "Get-Item " + q, stdout=asyncio.subprocess.PIPE)
    t, _ = await proc.communicate()
    # ok: python.xss
    make_response(t)
    proc = await asyncio.create_subprocess_exec("pwsh", "-File", q, stdout=asyncio.subprocess.PIPE)
    u, _ = await proc.communicate()
    # ok: python.xss
    make_response(u)
    proc = await asyncio.create_subprocess_exec("pwsh", q, stdout=asyncio.subprocess.PIPE)
    v, _ = await proc.communicate()
    # ok: python.xss
    make_response(v)
    proc = await asyncio.create_subprocess_exec("pwsh", "-NoLogo", q, stdout=asyncio.subprocess.PIPE)
    w, _ = await proc.communicate()
    # ok: python.xss
    make_response(w)
    proc = await asyncio.create_subprocess_exec("pwsh", "-WorkingDirectory", "/srv", q, stdout=asyncio.subprocess.PIPE)
    x, _ = await proc.communicate()
    # ok: python.xss
    make_response(x)
    proc = await asyncio.create_subprocess_exec("powershell", "-Version", "5.1", q, stdout=asyncio.subprocess.PIPE)
    y, _ = await proc.communicate()
    # ok: python.xss
    make_response(y)
    proc = await asyncio.create_subprocess_exec("powershell", "Get-Item", q, stdout=asyncio.subprocess.PIPE)
    z, _ = await proc.communicate()
    # ok: python.xss
    make_response(z)
    held = ["pwsh", "-Command", "Get-Item " + q]
    # ok: python.xss
    make_response(subprocess.check_output(held).decode())
    return "done"


# A program string or argument vector that is request data itself, in place, through a variable,
# or as a view parameter; and the vector unpacked into asyncio.create_subprocess_exec().
@app.route("/results/vectors/<arg>")
async def results_vectors(arg):
    a = subprocess.check_output(args=request.args["tool"])
    # ok: python.xss
    make_response(a)
    tool = request.args["tool"]
    b = subprocess.check_output(tool)
    # ok: python.xss
    make_response(b)
    form = request.form
    c = subprocess.check_output(form["tool"])
    # ok: python.xss
    make_response(c)
    d = subprocess.check_output(form["tool"].strip())
    # ok: python.xss
    make_response(d)
    e = subprocess.check_output(form.getlist("argv"))
    # ok: python.xss
    make_response(e)
    f = subprocess.check_output(form.getlist("argv").copy())
    # ok: python.xss
    make_response(f)
    g = subprocess.check_output(shlex.split(tool))
    # ok: python.xss
    make_response(g)
    h = subprocess.check_output(shlex.split(form["line"]))
    # ok: python.xss
    make_response(h)
    text = request.get_data(as_text=True)
    i = subprocess.check_output(shlex.split(text.strip()))
    # ok: python.xss
    make_response(i)
    j = subprocess.check_output(args=form["tool"])
    # ok: python.xss
    make_response(j)
    k = subprocess.check_output(args=form["tool"].strip())
    # ok: python.xss
    make_response(k)
    m = subprocess.check_output(args=form.getlist("argv"))
    # ok: python.xss
    make_response(m)
    n = subprocess.check_output(args=shlex.split(tool))
    # ok: python.xss
    make_response(n)
    line = form["line"]
    o = subprocess.check_output(line.split())
    # ok: python.xss
    make_response(o)
    stripped = form["line"].strip()
    p = subprocess.check_output(shlex.split(stripped))
    # ok: python.xss
    make_response(p)
    listed = form.getlist("argv")
    r = subprocess.check_output(args=listed)
    # ok: python.xss
    make_response(r)
    t = subprocess.check_output(arg)
    # ok: python.xss
    make_response(t)
    u = subprocess.check_output(arg.lower())
    # ok: python.xss
    make_response(u)
    v = subprocess.check_output(shlex.split(arg))
    # ok: python.xss
    make_response(v)
    w = subprocess.check_output(args=arg)
    # ok: python.xss
    make_response(w)
    proc = await asyncio.create_subprocess_exec(*request.form.getlist("argv"), stdout=asyncio.subprocess.PIPE)
    x, _ = await proc.communicate()
    # ok: python.xss
    make_response(x)
    vector = shlex.split(request.args["line"])
    proc = await asyncio.create_subprocess_exec(*vector, stdout=asyncio.subprocess.PIPE)
    y, _ = await proc.communicate()
    # ok: python.xss
    make_response(y)
    proc = await asyncio.create_subprocess_exec(*form.getlist("argv"), stdout=asyncio.subprocess.PIPE)
    z, _ = await proc.communicate()
    # ok: python.xss
    make_response(z)
    proc = await asyncio.create_subprocess_exec(*shlex.split(arg), stdout=asyncio.subprocess.PIPE)
    zz, _ = await proc.communicate()
    # ok: python.xss
    make_response(zz)
    return "done"


# The same Windows shells' lists held in a variable, and the remaining program and vector forms.
@app.route("/results/windows-held")
async def results_windows_held():
    q = request.args["q"]
    a = ("cmd", "/c", "dir " + q)
    # ok: python.xss
    make_response(subprocess.check_output(a).decode())
    b = ("pwsh", "-c", "Get-Item " + q)
    # ok: python.xss
    make_response(subprocess.check_output(b).decode())
    c = ["pwsh", "-cwa", "Get-Item " + q]
    # ok: python.xss
    make_response(subprocess.check_output(c).decode())
    d = ("pwsh", "-CommandWithArgs", "Get-Item " + q)
    # ok: python.xss
    make_response(subprocess.check_output(d).decode())
    e = ["pwsh", q]
    # ok: python.xss
    make_response(subprocess.check_output(e).decode())
    f = ("pwsh", q)
    # ok: python.xss
    make_response(subprocess.check_output(f).decode())
    g = ["pwsh", "-Login", q]
    # ok: python.xss
    make_response(subprocess.check_output(g).decode())
    h = ("pwsh", "-NoExit", q)
    # ok: python.xss
    make_response(subprocess.check_output(h).decode())
    i = ["pwsh", "-WindowStyle", "Hidden", q]
    # ok: python.xss
    make_response(subprocess.check_output(i).decode())
    j = ("pwsh", "-wd", "/srv", q)
    # ok: python.xss
    make_response(subprocess.check_output(j).decode())
    k = ["powershell", "-Version", "5.1", q]
    # ok: python.xss
    make_response(subprocess.check_output(k).decode())
    m = ("powershell", "-version", "5.1", q)
    # ok: python.xss
    make_response(subprocess.check_output(m).decode())
    n = ["powershell", "Get-Item", q]
    # ok: python.xss
    make_response(subprocess.check_output(n).decode())
    o = ("powershell", "Get-Item", q)
    # ok: python.xss
    make_response(subprocess.check_output(o).decode())
    loop = asyncio.get_running_loop()
    p = await loop.subprocess_exec(Collect, q)
    # ok: python.xss
    make_response(p)
    tool = request.args["tool"]
    r = subprocess.check_output(args=tool)
    # ok: python.xss
    make_response(r)
    form = request.form
    picked = form["tool"]
    s = subprocess.check_output(picked)
    # ok: python.xss
    make_response(s)
    copied = form.getlist("argv").copy()
    t = subprocess.check_output(copied)
    # ok: python.xss
    make_response(t)
    proc = await asyncio.create_subprocess_exec(*form["argv"], stdout=asyncio.subprocess.PIPE)
    u, _ = await proc.communicate()
    # ok: python.xss
    make_response(u)
    line = request.args["line"]
    proc = await asyncio.create_subprocess_exec(*shlex.split(line), stdout=asyncio.subprocess.PIPE)
    v, _ = await proc.communicate()
    # ok: python.xss
    make_response(v)
    proc = await asyncio.create_subprocess_exec(*shlex.split(form["line"]), stdout=asyncio.subprocess.PIPE)
    w, _ = await proc.communicate()
    # ok: python.xss
    make_response(w)
    return "done"


@api.post("/results/vectors")
async def fastapi_results_vectors(job: Job, extra: dict):
    a = subprocess.check_output(job.argv)
    # ok: python.xss
    HTMLResponse(a)
    b = subprocess.check_output(extra["argv"])
    # ok: python.xss
    HTMLResponse(b)
    c = subprocess.check_output(shlex.split(job.line))
    # ok: python.xss
    HTMLResponse(c)
    d = subprocess.check_output(args=job.argv)
    # ok: python.xss
    HTMLResponse(d)
    argv = job.argv
    e = subprocess.check_output(argv)
    # ok: python.xss
    HTMLResponse(e)
    ee = subprocess.check_output(args=argv)
    # ok: python.xss
    HTMLResponse(ee)
    proc = await asyncio.create_subprocess_exec(*job.argv, stdout=asyncio.subprocess.PIPE)
    f, _ = await proc.communicate()
    # ok: python.xss
    HTMLResponse(f)
    proc = await asyncio.create_subprocess_exec(*job, stdout=asyncio.subprocess.PIPE)
    g, _ = await proc.communicate()
    # ok: python.xss
    HTMLResponse(g)
    proc = await asyncio.create_subprocess_exec(*job.lines(), stdout=asyncio.subprocess.PIPE)
    h, _ = await proc.communicate()
    # ok: python.xss
    HTMLResponse(h)
    proc = await asyncio.create_subprocess_exec(*shlex.split(job.line), stdout=asyncio.subprocess.PIPE)
    i, _ = await proc.communicate()
    # ok: python.xss
    HTMLResponse(i)
    return "done"


def django_results(request):
    out = subprocess.check_output("finger " + request.GET["user"], shell=True, text=True)
    # ok: python.xss
    return HttpResponse("<pre>" + out + "</pre>")


def django_results_file(request, name):
    with open(os.path.join(PAGES, name)) as page:
        text = page.read()
    # ok: python.xss
    return HttpResponse(text)


def django_results_fetch(request):
    page = requests.post(request.POST["hook"], json={"ping": 1}).text
    # ruleid: python.xss
    return HttpResponse(page)


@api.get("/results/fetch", response_class=HTMLResponse)
async def fastapi_results_fetch(url: str):
    async with httpx.AsyncClient() as client:
        reply = await client.get(url)
    # ruleid: python.xss
    return reply.text


@api.get("/results/echo")
async def fastapi_results_echo(msg: str):
    out = subprocess.check_output(["echo", msg], text=True)
    # ruleid: python.xss
    return HTMLResponse("<p>" + out + "</p>")


@api.get("/results/shell")
async def fastapi_results_shell(host: str):
    out = subprocess.check_output(["bash", "-c", "dig " + host], text=True)
    # ok: python.xss
    return HTMLResponse("<pre>" + out + "</pre>")
