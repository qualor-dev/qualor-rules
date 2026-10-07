import html
import json
from urllib import parse
from urllib.parse import urlparse
from typing import Annotated

import bleach
import markupsafe
import nh3
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


# A helper's result kept in a variable and returned whole is still taken for text.
@app.route("/api/summary/<slug>")
def api_summary(slug):
    summary = find_post(slug).to_dict()
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
