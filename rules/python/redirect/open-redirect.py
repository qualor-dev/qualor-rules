from typing import Annotated
from urllib import parse
from urllib.parse import urlencode, urlparse, urlsplit

from django.conf import settings
from django.http import HttpResponsePermanentRedirect, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect as django_redirect
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django_hosts.resolvers import reverse as hosts_reverse
from fastapi import Depends, FastAPI, Path, Query, Request
from fastapi.responses import RedirectResponse
from flask import Flask, redirect, request, url_for
from pydantic import BaseModel

from .forms import NextForm
from .models import Article

app = Flask(__name__)
api = FastAPI()

SITE = "https://www.example.com"
SITE_ROOT = "https://www.example.com/"
OAUTH_ROOT = "https://accounts.example.com/"
DESTINATIONS = {
    # Partner sites the app may send users to.
    "docs": "https://docs.example.com/",
    "status": "https://status.example.com/",  # status page
}
# Changed later by a view, so not an allow-list.
CAMPAIGNS = {"spring": "https://www.example.com/spring"}


# Flask: query strings, form fields, JSON bodies, cookies, headers and URL variables.
@app.route("/login")
def login():
    next_url = request.args.get("next")
    # ruleid: python.open-redirect
    return redirect(next_url)


@app.post("/logout")
def logout():
    # ruleid: python.open-redirect
    return redirect(request.form["return_to"], code=303)


@app.post("/api/continue")
def api_continue():
    data = request.get_json()
    # ruleid: python.open-redirect
    return redirect(data["url"])


@app.route("/back")
def back():
    # ruleid: python.open-redirect
    return redirect(request.cookies.get("last_page") or url_for("index"))


@app.route("/go/<path:target>")
def go(target):
    # ruleid: python.open-redirect
    return redirect("https://" + target)


@app.route("/jump")
def jump():
    # ruleid: python.open-redirect
    return redirect(f"//{request.args['host']}/welcome")


@app.route("/forward")
def forward():
    # ruleid: python.open-redirect
    return redirect(SITE + request.args["path"])


@app.route("/slash")
def slash():
    # "/" + "/evil.example" is a network-path reference.
    # ruleid: python.open-redirect
    return redirect("/" + request.args["path"])


# Flask: url_for(), relative paths, fixed origins, allow-lists and constants.
@app.route("/profile")
def profile():
    # ok: python.open-redirect
    return redirect(url_for("user", name=request.args["name"]))


@app.route("/item/<item_id>")
def item(item_id):
    # ok: python.open-redirect
    a = redirect("/items/" + item_id)
    # ok: python.open-redirect
    b = redirect(f"/items/{item_id}?ref={request.args['ref']}")
    # ok: python.open-redirect
    c = redirect("https://www.example.com/items/" + item_id)
    # ok: python.open-redirect
    d = redirect(SITE + "/items/" + item_id)
    # ok: python.open-redirect
    e = redirect(f"{SITE}/items/{item_id}")
    # ok: python.open-redirect
    f = redirect(SITE_ROOT + item_id)
    # ok: python.open-redirect
    g = redirect("{}/items/{}".format(SITE, item_id))
    # ok: python.open-redirect
    return redirect(url_for("item_page", item_id=int(item_id)))


@app.route("/secure")
def force_https():
    # ok: python.open-redirect
    return redirect(request.url.replace("http://", "https://", 1), code=301)


@app.route("/find")
def find():
    # ok: python.open-redirect
    a = redirect(url_for("search") + "?q=" + request.args["q"])
    target = url_for("search")
    target += "?q=" + request.args["q"] + "&page=" + request.args.get("page", "1")
    # ok: python.open-redirect
    b = redirect(target)
    base = url_for("search")
    # ok: python.open-redirect
    c = redirect(base + "?q=" + request.args["q"])
    # ok: python.open-redirect
    return redirect(f"{url_for('search')}?q={request.args['q']}")


@app.route("/after-login")
def after_login():
    next_page = request.args.get("next")
    if not next_page or urlsplit(next_page).netloc != "":
        next_page = None
    # A netloc check alone lets "/\\evil.example" through: browsers read the backslash as "/".
    # ruleid: python.open-redirect
    return redirect(next_page or "/")


# Parsing the URL with urllib.parse keeps its host: urlparse("////evil.example/x").path is
# "//evil.example/x".
@app.route("/continue")
def continue_to():
    parts = urlsplit(request.args["next"])
    # ruleid: python.open-redirect
    a = redirect(parts.scheme + "://" + parts.netloc + parts.path)
    # ruleid: python.open-redirect
    b = redirect(urlparse(request.args["next"]).path)
    nxt = request.form["next"]
    if not (target := urlparse(nxt)):
        return redirect("/")
    # ruleid: python.open-redirect
    return redirect(target.path)


# A constant origin ending in "/" followed by more text.
@app.route("/continue2")
def continue2():
    # ruleid: python.open-redirect
    return redirect(parse.urlparse(request.args["next"]).path)


# An object built in place from a subscripted request value is taken for stored data.
class Target:
    def __init__(self, url):
        self.url = url


@app.route("/continue3")
def continue3():
    # todoruleid: python.open-redirect
    return redirect(Target(request.args["next"]).url)


# More than five operands after a constant ending in "host/" are not recognised.
@app.route("/long-chain")
def long_chain():
    # todook: python.open-redirect
    return redirect(SITE_ROOT + "a/" + "b/" + "c/" + "d/" + request.args["page"])


@app.route("/authorize")
def authorize():
    # ok: python.open-redirect
    return redirect(SITE_ROOT + "authorize?" + urlencode({"state": request.args["state"]}))


# Nested tables and implicitly concatenated values are not recognised as allow-lists; an
# upper-case local is not a constant.
NESTED_DESTINATIONS = {"docs": {"en": "https://docs.example.com/en/"}}
JOINED_DESTINATIONS = {"docs": ("https://docs.example.com/" "latest/")}


@app.route("/out2/<name>")
def out2(name):
    # todook: python.open-redirect
    a = redirect(NESTED_DESTINATIONS[name]["en"])
    # todook: python.open-redirect
    b = redirect(JOINED_DESTINATIONS[name])
    FALLBACK = request.args["fallback"]
    # ruleid: python.open-redirect
    return redirect(DESTINATIONS.get(name, FALLBACK))


@app.route("/out/<name>")
def out(name):
    # ok: python.open-redirect
    a = redirect(DESTINATIONS.get(name, DESTINATIONS["docs"]))
    # ok: python.open-redirect
    b = redirect(DESTINATIONS[name] if name in DESTINATIONS else "/")
    # ruleid: python.open-redirect
    c = redirect(DESTINATIONS.get(name, request.args["fallback"]))
    # ruleid: python.open-redirect
    return redirect(CAMPAIGNS[name])


@app.post("/campaigns")
def add_campaign():
    CAMPAIGNS[request.form["name"]] = request.form["url"]
    return "", 204


# Look-alike: another object's redirect() method.
class Wizard:
    def redirect(self, step):
        return "step %s" % step


@app.route("/wizard")
def wizard():
    # ok: python.open-redirect
    return Wizard().redirect(request.args["step"])


# A host check of the parsed URL is not recognised.
@app.route("/checked")
def checked():
    target = request.args["next"]
    parsed = urlparse(target)
    if parsed.scheme != "https" or parsed.netloc != "www.example.com":
        target = "/"
    # todook: python.open-redirect
    return redirect(target)


# A membership check against an allow-list is not recognised.
@app.route("/section")
def section():
    s = request.args["s"]
    if s not in ("/news", "/blog"):
        s = "/"
    # todook: python.open-redirect
    return redirect(s)


# %-formatting with a constant origin is not recognised.
@app.route("/legacy-item/<item_id>")
def legacy_item(item_id):
    # todook: python.open-redirect
    return redirect("%s/items/%s" % (SITE, item_id))


# Flask typed converter: the rule cannot see that <int:n> is an int.
@app.route("/page/<int:num>")
def page(num):
    # todook: python.open-redirect
    return redirect("//cdn.example.com/pages/%d" % num)


# A Flask view parameter annotated int is not a source, although Flask passes a str for a
# <name> rule without a converter.
@app.route("/legacy/<legacy_host>")
def legacy(legacy_host: int):
    # todoruleid: python.open-redirect
    return redirect("https://" + legacy_host)


# A slice of request data: OpenGrep does not carry taint through a slice, so the rule takes a
# slice of a request value (in place or through a variable) or of a view parameter as request
# data itself. A slice of a value built from request data is missed.
# A slice of the current URL or path stays on this site.
@app.route("/trimmed")
def trimmed():
    target = request.args.get("next", "/")
    # ruleid: python.open-redirect
    response = redirect(target[:200])
    # todoruleid: python.open-redirect
    response = redirect((request.args["next"] + "#top")[:200])
    trimmed = request.args.get("next", "/")
    trimmed = trimmed.strip()
    # todoruleid: python.open-redirect
    response = redirect(trimmed[:200])
    # ok: python.open-redirect
    response = redirect(request.full_path[:-1])
    # ruleid: python.open-redirect
    return redirect(request.args["next"][:200])


# Django: redirect(), HttpResponseRedirect and HttpResponsePermanentRedirect.
def django_login(request):
    next_url = request.GET.get("next", "/")
    # ruleid: python.open-redirect
    return HttpResponseRedirect(next_url)


def django_moved(request, slug):
    # ruleid: python.open-redirect
    return HttpResponsePermanentRedirect("https://" + slug + ".example.com/")


def django_after_post(request):
    # ruleid: python.open-redirect
    return django_redirect(request.POST["success_url"])


class ContinueView(View):
    def get(self, request, *args, **kwargs):
        # ruleid: python.open-redirect
        return django_redirect(self.request.GET["to"])


def django_safe(request, slug):
    # ok: python.open-redirect
    a = django_redirect("article-detail", slug=slug)
    # ok: python.open-redirect
    b = HttpResponseRedirect(reverse("article-detail", kwargs={"slug": slug}))
    # ok: python.open-redirect
    c = django_redirect(f"/articles/{slug}/")
    # ok: python.open-redirect
    d = HttpResponseRedirect(settings.SITE_URL + "/articles/" + slug)
    # ok: python.open-redirect
    e = HttpResponsePermanentRedirect(request.build_absolute_uri().replace("http://", "https://", 1))
    # ok: python.open-redirect
    return django_redirect(f"{settings.SITE_URL}/articles/{request.GET['page']}")


def django_article(request, slug):
    # ok: python.open-redirect
    a = django_redirect(Article.objects.get(slug=slug))
    article = get_object_or_404(Article, slug=slug)
    # ok: python.open-redirect
    b = django_redirect(article)
    # ok: python.open-redirect
    c = HttpResponseRedirect(article.external_url)
    search_url = reverse("search")
    search_url += "?q=%s" % request.GET["q"]
    # ok: python.open-redirect
    d = django_redirect(search_url)
    docs_url = hosts_reverse("document-search", host="docs")
    docs_url += "?q=" + request.GET["q"]
    # ok: python.open-redirect
    e = HttpResponseRedirect(docs_url)
    if not (mirror := getattr(article, request.GET["kind"], None)):
        return django_redirect("home")
    # ok: python.open-redirect
    f = HttpResponsePermanentRedirect(mirror.url)
    # ok: python.open-redirect
    return HttpResponsePermanentRedirect(request.get_full_path().replace("/old/", "/new/", 1))


# The current path changed with a request value as the text to replace is taken for request data.
def django_version(request, version):
    path = request.get_full_path()
    # todook: python.open-redirect
    return django_redirect(path.replace(version, "stable", 1))


# A form built from request data: its cleaned_data is still the request's text.
def django_form_next(request):
    form = NextForm(request.POST)
    if form.is_valid():
        # ruleid: python.open-redirect
        return HttpResponseRedirect(form.cleaned_data["next"])
    return django_redirect("home")


# Request data that reaches a form through a variable is taken for stored data.
def django_form_data(request):
    data = request.POST
    form = NextForm(data)
    if form.is_valid():
        # todoruleid: python.open-redirect
        return HttpResponseRedirect(form.cleaned_data["next"])
    return django_redirect("home")


# The current request's path is taken for a path on this site, but a path that begins with "//"
# (a catch-all URL pattern reaches the view with it) names another host.
def django_catch_all(request, rest):
    # todoruleid: python.open-redirect
    return HttpResponsePermanentRedirect(request.path + "/")


# Django's url_has_allowed_host_and_scheme() check (a private API) is not recognised.
def django_next(request):
    next_url = request.GET.get("next", "")
    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        next_url = "/"
    # todook: python.open-redirect
    return HttpResponseRedirect(next_url)


# path("pages/<int:pk>/", views.django_page): the converter is in urls.py.
def django_page(request, pk):
    # todook: python.open-redirect
    return HttpResponseRedirect("//cdn.example.com/%s" % pk)


# A default value: Django passes the URL value when the pattern captures one.
def django_home(request, home="/"):
    # todook: python.open-redirect
    return HttpResponseRedirect(home)


# Helpers whose first parameter is named request look like views: other parameters count as URL
# arguments, and an outgoing request (an HTTP client's) has its headers taken as request data.
def redirect_to(request, url):
    # todook: python.open-redirect
    return HttpResponseRedirect(url)


def follow_upstream(request):
    # todook: python.open-redirect
    return HttpResponseRedirect(request.headers["Location"])


# FastAPI: RedirectResponse, and a path operation with response_class=RedirectResponse.
class Checkout(BaseModel):
    cart_id: str
    return_url: str


@api.get("/sso")
async def sso(next: str = "/"):
    # ruleid: python.open-redirect
    return RedirectResponse(next)


@api.post("/checkout")
async def checkout(order: Checkout):
    # ruleid: python.open-redirect
    return RedirectResponse(url=order.return_url, status_code=303)


@api.get("/r/{target}", response_class=RedirectResponse)
async def short_link(target: str):
    # ruleid: python.open-redirect
    return "https://" + target


@api.get("/home")
async def home(request: Request, tab: str = ""):
    # ok: python.open-redirect
    https = RedirectResponse(str(request.url.replace(scheme="https")))
    # ok: python.open-redirect
    base = RedirectResponse(str(request.base_url) + "dashboard/" + tab)
    # ok: python.open-redirect
    dash = RedirectResponse(api.url_path_for("dashboard") + "?tab=" + tab)
    # ok: python.open-redirect
    login = RedirectResponse(OAUTH_ROOT + "authorize?state=" + tab + "&scope=read")
    # ok: python.open-redirect
    a = RedirectResponse(request.url_for("dashboard"))
    # ok: python.open-redirect
    b = RedirectResponse(url="/dashboard/" + tab)
    # ok: python.open-redirect
    return RedirectResponse(f"/dashboard?tab={tab}")


class Settings(BaseModel):
    portal_url: str = "https://portal.example.com/"


def get_settings():
    return Settings()


SettingsDep = Annotated[Settings, Depends(get_settings)]


@api.get("/portal/{section}")
async def portal(
    section: Annotated[int, Path()],
    settings: SettingsDep,
    other: Annotated[Settings, Depends(get_settings)],
    legacy: Settings = Depends(get_settings),
    to: Annotated[str, Query()] = "",
):
    # ok: python.open-redirect
    a = RedirectResponse(settings.portal_url)
    # ok: python.open-redirect
    b = RedirectResponse(other.portal_url + str(section))
    # ok: python.open-redirect
    c = RedirectResponse(legacy.portal_url)
    # ruleid: python.open-redirect
    return RedirectResponse(to)
