import os
import re
from typing import Annotated
from urllib import parse
from urllib.parse import urlencode, urlparse, urlsplit

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponsePermanentRedirect,
    HttpResponseRedirect,
    JsonResponse,
    StreamingHttpResponse,
)
from django.shortcuts import get_object_or_404, resolve_url
from django.shortcuts import redirect as django_redirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin
from django.utils.http import is_safe_url, url_has_allowed_host_and_scheme
from django.views import View
from django.views.generic import RedirectView
from django_hosts.resolvers import reverse as hosts_reverse
from fastapi import Depends, FastAPI, Path, Query, Request
from fastapi import Response as FastAPIResponse
from fastapi.responses import HTMLResponse, RedirectResponse
from flask import Flask, Response, current_app, make_response, redirect, request, url_for
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from . import links
from .config import PORTAL_ROOT
from .forms import NextForm
from .models import Article

app = Flask(__name__)
api = FastAPI()

SITE = "https://www.example.com"
SITE_ROOT = "https://www.example.com/"
OAUTH_ROOT = "https://accounts.example.com/"
SCHEME = "https:"
ENV_SITE = os.environ["SITE_URL"]
CFG_SITE = os.environ.get("SITE_URL", "https://www.example.com")
URL_PREFIX = "/app"
ROOT_SLASH = "/"
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


# A constant counts as an origin only when the module assigns it a literal with a scheme and a
# host, and only before a separator: "https:" + "//" + host names any host.
@app.route("/hop")
def hop():
    host = request.args["host"]
    # ruleid: python.open-redirect
    a = redirect(SCHEME + "//" + host + "/welcome")
    # ruleid: python.open-redirect
    b = redirect(f"{SCHEME}//{host}/welcome")
    # ruleid: python.open-redirect
    c = redirect("{}//{}/welcome".format(SCHEME, host))
    # "//" after a constant is refused even when the constant holds a host (conservative).
    # ruleid: python.open-redirect
    k = redirect(SITE + "//" + host)
    NEXT_URL = request.args["next"]
    # An upper-case local that holds request data is not a constant.
    # ruleid: python.open-redirect
    d = redirect(NEXT_URL + "/done")
    # ok: python.open-redirect
    e = redirect(SITE + "?ref=" + host)
    # ok: python.open-redirect
    return redirect(SITE + "/hosts/" + host + "/" + request.args["tab"] + "/" + request.args["page"])


# A constant imported or read from the environment: its value is unknown, but a path segment, a
# query or a fragment after it stays on a fixed origin (an empty value leaves a local path).
@app.route("/portal-item/<item_id>")
def portal_item(item_id):
    # ok: python.open-redirect
    return redirect(PORTAL_ROOT + "/items/" + item_id)


@app.route("/env-item/<item_id>")
def env_item(item_id):
    # ok: python.open-redirect
    a = redirect(ENV_SITE + "/items/" + item_id)
    # ok: python.open-redirect
    b = redirect(CFG_SITE + "/items/" + item_id)
    # ok: python.open-redirect
    c = redirect(f"{ENV_SITE}/items/{item_id}")
    # ok: python.open-redirect
    d = redirect("{}/items/{}".format(ENV_SITE, item_id))
    # ok: python.open-redirect
    e = redirect(ENV_SITE + "?item=" + item_id)
    # A bare "/" after a value that may be empty can start "//host".
    # ruleid: python.open-redirect
    f = redirect(ENV_SITE + "/" + item_id)
    # ruleid: python.open-redirect
    g = redirect(f"{ENV_SITE}//{item_id}")
    # A constant path on this site keeps what follows on this site.
    # ok: python.open-redirect
    h = redirect(URL_PREFIX + "/items/" + item_id)
    # "/" alone is not a path prefix: "/" + "/evil.example" names another host.
    # ruleid: python.open-redirect
    i = redirect(ROOT_SLASH + request.args["host"])
    # Flask's app.config is not recognised as an origin.
    # todook: python.open-redirect
    return redirect(current_app.config["SITE_URL"] + "/items/" + item_id)


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


# Flask before_request hooks run for every path. Werkzeug drops the leading slashes of
# request.path but keeps "/\\evil.example" (from "/%5Cevil.example"), which browsers read as
# "//evil.example", and its redirect() does not escape the backslash: there the current path
# is request data.
@app.before_request
def strip_trailing_slash():
    if request.path != "/" and request.path.endswith("/"):
        # ruleid: python.open-redirect
        return redirect(request.path[:-1])
    if request.path != request.path.lower():
        # ruleid: python.open-redirect
        return redirect(request.full_path.lower())
    if not request.is_secure:
        # ok: python.open-redirect
        return redirect(request.url.replace("http://", "https://", 1))
    if request.path.startswith("/account/"):
        # ok: python.open-redirect
        return redirect("/login?next=" + request.full_path)
    if "//" in request.path:
        # Collapsing slashes leaves the backslash in place.
        # todoruleid: python.open-redirect
        return redirect(re.sub("/+", "/", request.path))
    return None


# In a view, the current path is taken for a path on this site; a catch-all rule reaches the
# view with "/\\evil.example" too.
@app.route("/files/<path:rest>")
def files_catch_all(rest):
    # todoruleid: python.open-redirect
    return redirect(request.path + "/")


# A Location header set on a response redirects as well: Flask's response headers, its
# location attribute, a view's (body, status, headers) tuple and an after_request hook.
@app.route("/moved")
def moved():
    resp = make_response("", 302)
    # ruleid: python.open-redirect
    resp.headers["Location"] = request.args["to"]
    return resp


@app.route("/moved-tuple")
def moved_tuple():
    # ruleid: python.open-redirect
    return "", 302, {"Location": request.args["to"]}


@app.route("/moved-attr")
def moved_attr():
    resp = Response(status=301)
    # ruleid: python.open-redirect
    resp.location = request.args["to"]
    # ruleid: python.open-redirect
    resp.headers.set("location", request.args["to"])
    return resp


@app.route("/moved-ok")
def moved_ok():
    resp = Response(status=302, headers={"Location": url_for("index")})
    # ok: python.open-redirect
    resp.headers["X-Ref"] = request.args.get("ref", "")
    # ok: python.open-redirect
    resp.headers["Location"] = "/items/" + request.args["item"]
    # ok: python.open-redirect
    return "", 302, {"Location": url_for("index"), "X-Ref": request.args.get("ref", "")}


@app.after_request
def add_location(response):
    if response.status_code == 302 and "next" in request.args:
        # ruleid: python.open-redirect
        response.headers["Location"] = request.args["next"]
    return response


# A dict that is not a response is not a header (an exported row with a Location column).
@app.post("/export-row")
def export_row():
    row = {"Name": request.form["name"]}
    # ok: python.open-redirect
    row["Location"] = request.form["city"]
    return row


# Headers collected in a dict first are not followed.
@app.route("/moved-dict")
def moved_dict():
    headers = {"Location": request.args["to"]}
    # todoruleid: python.open-redirect
    return Response(status=302, headers=headers)


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


# Django's url_has_allowed_host_and_scheme() check (is_safe_url() before Django 3.0): the
# redirect inside the checked branch, after an early return or raise, or after the value is
# replaced with a fixed one, stays on an allowed host.
def django_next(request):
    next_url = request.GET.get("next", "")
    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        next_url = "/"
    # ok: python.open-redirect
    return HttpResponseRedirect(next_url)


def django_guarded(request):
    next_url = request.GET.get("next", "")
    if url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        # ok: python.open-redirect
        return HttpResponseRedirect(next_url)
    return django_redirect("home")


def django_guarded_and(request):
    next_url = request.POST.get("next")
    if next_url and url_has_allowed_host_and_scheme(
        url=next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        # ok: python.open-redirect
        return django_redirect(next_url)
    return django_redirect("home")


def django_early_return(request):
    target = request.POST.get("next", "")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        return HttpResponseBadRequest("unsafe next")
    # ok: python.open-redirect
    return HttpResponseRedirect(target)


def django_early_raise(request):
    target = request.GET["next"]
    if not target or not url_has_allowed_host_and_scheme(target, {request.get_host()}):
        raise PermissionDenied
    # ok: python.open-redirect
    return django_redirect(target)


def django_checked_then_more(request):
    target = request.GET.get("next", "")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts=None):
        return HttpResponseRedirect("/")
    if not request.user.is_staff:
        # ok: python.open-redirect
        return HttpResponseRedirect(target)
    return HttpResponseRedirect("/staff/")


def django_ternary(request):
    target = request.GET.get("next", "")
    # ok: python.open-redirect
    return HttpResponseRedirect(target if url_has_allowed_host_and_scheme(target, allowed_hosts=None) else "/")


def django_stored_check(request):
    redirect_to = request.POST.get("next", "")
    url_is_safe = url_has_allowed_host_and_scheme(
        url=redirect_to, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    )
    # ok: python.open-redirect
    a = HttpResponseRedirect(redirect_to if url_is_safe else "/")
    if url_is_safe:
        # ok: python.open-redirect
        return HttpResponseRedirect(redirect_to)
    return HttpResponseRedirect("/")


def django_old_check(request):
    target = request.GET.get("next", "")
    if is_safe_url(target, allowed_hosts={request.get_host()}):
        # ok: python.open-redirect
        return HttpResponseRedirect(target)
    return HttpResponseRedirect("/")


# The check guards only what it checks, only where it holds.
def django_inverted_check(request):
    target = request.GET.get("next", "")
    if url_has_allowed_host_and_scheme(target, allowed_hosts=None):
        return HttpResponseRedirect("/")
    else:
        # ruleid: python.open-redirect
        return HttpResponseRedirect(target)


def django_wrong_branch(request):
    target = request.GET.get("next", "")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts=None):
        # ruleid: python.open-redirect
        return HttpResponseRedirect(target)
    return HttpResponseRedirect("/")


def django_redirect_before_check(request):
    target = request.GET.get("next", "")
    safe = url_has_allowed_host_and_scheme(target, allowed_hosts=None)
    # ruleid: python.open-redirect
    response = HttpResponseRedirect(target)
    if not safe:
        return HttpResponseRedirect("/")
    return response


def django_check_without_exit(request):
    target = request.GET["next"]
    if not url_has_allowed_host_and_scheme(target, allowed_hosts=None):
        print("unsafe next", target)
    # ruleid: python.open-redirect
    return django_redirect(target)


def django_checked_other(request):
    target = request.GET["next"]
    fallback = request.GET["fallback"]
    if url_has_allowed_host_and_scheme(target, allowed_hosts=None):
        # ruleid: python.open-redirect
        return django_redirect(fallback)
    return django_redirect("home")


def django_ternary_fallback(request):
    target = request.GET.get("next", "")
    # ruleid: python.open-redirect
    return HttpResponseRedirect(target if url_has_allowed_host_and_scheme(target, None) else request.GET["back"])


def django_replaced_with_request(request):
    target = request.GET.get("next", "")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts=None):
        target = request.GET["back"]
    # ruleid: python.open-redirect
    return HttpResponseRedirect(target)


def django_replaced_with_built(request):
    target = request.GET.get("next", "")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts=None):
        target = "https://" + request.GET["host"]
    # ruleid: python.open-redirect
    return HttpResponseRedirect(target)


def django_replaced_with_resolved(request):
    target = request.GET.get("next", "")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts=None):
        target = resolve_url(request.GET["back"])
    # ruleid: python.open-redirect
    return HttpResponseRedirect(target)


def django_else_of_failing_check(request):
    target = request.GET.get("next", "")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        # ruleid: python.open-redirect
        return HttpResponseRedirect(target)
    else:
        # ok: python.open-redirect
        return HttpResponseRedirect(target)


def django_elif_check(request):
    target = request.GET.get("next", "")
    if not target:
        return HttpResponseRedirect("/")
    elif url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        # ok: python.open-redirect
        return HttpResponseRedirect(target)
    else:
        # ruleid: python.open-redirect
        return HttpResponseRedirect(target)


def django_own_check(request):
    target = request.GET.get("next", "")
    if links.is_safe_url(target):
        # Another library's (or the project's own) check is not Django's.
        # ruleid: python.open-redirect
        return HttpResponseRedirect(target)
    return HttpResponseRedirect("/")


# allowed_hosts taken from the request lets that host through; not recognised.
def django_hosts_from_query(request):
    target = request.GET.get("next", "")
    if url_has_allowed_host_and_scheme(target, allowed_hosts={request.GET["host"]}):
        # todoruleid: python.open-redirect
        return HttpResponseRedirect(target)
    return HttpResponseRedirect("/")


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


# Django middleware sees every request path, also "//evil.example/" (Django keeps the leading
# slashes; the CVE-2018-14574 class): there the current path is request data, and a redirect
# that starts with it names another host. After a host, it stays on that host.
class AppendSlashMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if not path.endswith("/"):
            # ruleid: python.open-redirect
            return HttpResponsePermanentRedirect(path + "/")
        cleaned = re.sub("//+", "/", path)
        if cleaned != path:
            # ok: python.open-redirect
            return HttpResponsePermanentRedirect(cleaned)
        if request.path.startswith("/old/"):
            # ruleid: python.open-redirect
            return HttpResponseRedirect(request.get_full_path().replace("/old/", "/new/", 1))
        if request.path != request.path.lower():
            # Doubled slashes collapsed: the path stays on this site.
            # ok: python.open-redirect
            return HttpResponsePermanentRedirect(re.sub(r"/+", "/", request.path.lower()))
        if not request.is_secure():
            # ok: python.open-redirect
            return HttpResponsePermanentRedirect(request.build_absolute_uri().replace("http://", "https://", 1))
        if request.get_host() == "example.com":
            # ok: python.open-redirect
            return HttpResponsePermanentRedirect("https://www.example.com" + request.get_full_path())
        if request.get_host() == "old.example.com":
            # ok: python.open-redirect
            return HttpResponsePermanentRedirect(SITE + request.get_full_path())
        if request.path.startswith("/account/") and not request.user.is_authenticated:
            # ok: python.open-redirect
            return HttpResponseRedirect("/login/?next=" + request.get_full_path())
        if request.path.startswith("/shop/"):
            # ok: python.open-redirect
            return HttpResponseRedirect(f"https://{request.get_host()}{request.path}?ref=shop")
        if request.path.startswith("/blog/"):
            # ok: python.open-redirect
            return HttpResponseRedirect("https://" + request.get_host() + request.path.replace("/blog/", "/news/", 1))
        if request.path.startswith("/next/"):
            # ruleid: python.open-redirect
            return HttpResponseRedirect("https://" + request.GET["host"] + request.path)
        if request.path.startswith("/m/"):
            # %-formatting with a host before the current path is not recognised.
            # todook: python.open-redirect
            return HttpResponseRedirect("https://%s%s" % (request.get_host(), request.path[2:]))
        return self.get_response(request)


class LoginRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith("/account/") and not request.user.is_authenticated:
            # A setting followed by a query or a path segment stays on its origin.
            # ok: python.open-redirect
            return django_redirect(settings.LOGIN_URL + "?next=" + request.path)
        if request.path.startswith("/orders/") and not request.user.is_authenticated:
            # ok: python.open-redirect
            return django_redirect(f"{settings.LOGIN_URL}?next={request.get_full_path()}")
        if request.path.startswith("/cart/") and not request.user.is_authenticated:
            # ok: python.open-redirect
            return django_redirect("%s?next=%s" % (settings.LOGIN_URL, request.path))
        if request.path.startswith("/mirror/"):
            # A bare "/" after a setting: an empty setting leaves "//" + path.
            # ruleid: python.open-redirect
            return django_redirect(settings.MIRROR_URL + "/" + request.path)
        return self.get_response(request)


class LegacyPathMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.path_info.startswith("/v1/"):
            # ruleid: python.open-redirect
            return django_redirect(request.path_info.replace("/v1/", "/v2/", 1))
        return None

    def process_view(self, request, view_func, view_args, view_kwargs):
        if request.path.endswith("/index"):
            # ruleid: python.open-redirect
            return HttpResponseRedirect(request.path[:-5])
        return None

    def process_response(self, request, response):
        if response.status_code == 404 and not request.path.endswith("/"):
            # ruleid: python.open-redirect
            return HttpResponsePermanentRedirect(f"{request.get_full_path()}/")
        return response


def lowercase_middleware(get_response):
    def middleware(request):
        if request.path != request.path.lower():
            # ruleid: python.open-redirect
            return django_redirect(request.path.lower())
        return get_response(request)

    return middleware


# Django: a Location header set on a response, also in middleware, and RedirectView's
# get_redirect_url() (its *args and **kwargs are the URL arguments).
def django_location_header(request):
    target = request.GET.get("next", "/")
    response = HttpResponse(status=302)
    # ruleid: python.open-redirect
    response["Location"] = target
    # ruleid: python.open-redirect
    response.headers["location"] = request.GET["back"]
    # ok: python.open-redirect
    response["Location"] = reverse("home")
    # ok: python.open-redirect
    response["X-Next"] = target
    return response


def django_created(request, pk):
    resp = HttpResponse(status=201)
    # ok: python.open-redirect
    resp["Location"] = request.build_absolute_uri(reverse("item-detail", args=[pk]))
    # ok: python.open-redirect
    resp.headers["Location"] = request.build_absolute_uri("/items/")
    # ruleid: python.open-redirect
    resp["Location"] = request.build_absolute_uri(request.GET["next"])
    # The header name is matched as "Location" or "location"; other spellings are missed.
    # todoruleid: python.open-redirect
    resp["LOCATION"] = request.GET["next"]
    return resp


def django_streamed_location(request):
    resp = StreamingHttpResponse(iter([b""]), status=302)
    # ruleid: python.open-redirect
    resp["Location"] = request.GET["next"]
    return resp


def django_location_init(request):
    # ruleid: python.open-redirect
    a = HttpResponse(status=303, headers={"Location": request.POST["next"]})
    # ok: python.open-redirect
    return HttpResponse(status=303, headers={"Location": "/thanks/", "X-From": request.GET.get("from", "")})


def django_export_row(request):
    row = {"Name": request.POST["name"]}
    # ok: python.open-redirect
    row["Location"] = request.POST["city"]
    return JsonResponse(row)


class BackLinkMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        if response.status_code == 302 and "back" in request.GET:
            # ruleid: python.open-redirect
            response["Location"] = request.GET["back"]
        return response


class NextRedirectView(RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        # ruleid: python.open-redirect
        return self.request.GET.get("next", "/")


class HostRedirectView(RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        # ruleid: python.open-redirect
        return "https://" + kwargs["host"] + "/"


class CounterRedirectView(RedirectView):
    pattern_name = "article-detail"

    def get_redirect_url(self, *args, **kwargs):
        article = get_object_or_404(Article, pk=kwargs["pk"])
        article.visits += 1
        article.save()
        # ok: python.open-redirect
        return super().get_redirect_url(*args, **kwargs)


class SearchRedirectView(RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        # ok: python.open-redirect
        return reverse("search") + "?q=" + self.request.GET.get("q", "")


# Not a RedirectView: its get_redirect_url() is not a redirect.
class ShareLink(View):
    def get_redirect_url(self):
        # ok: python.open-redirect
        return self.request.GET.get("next", "/")


# RedirectView's url with a placeholder filled from the URL arguments is not followed.
class PlaceholderRedirectView(RedirectView):
    # todoruleid: python.open-redirect
    url = "https://%(host)s/"


# get_redirect_url() is the view's method only when written directly in the RedirectView
# subclass: one defined under an if is missed; a nested function or a nested class's method of
# that name is not the view's (Django never calls it).
class FlaggedRedirectView(RedirectView):
    if settings.DEBUG:
        def get_redirect_url(self, *args, **kwargs):
            # todoruleid: python.open-redirect
            return kwargs["target"]


class HelperRedirectView(RedirectView):
    def get(self, *args, **kwargs):
        def get_redirect_url(target):
            # ok: python.open-redirect
            return target
        return super().get(*args, **kwargs)

    class Links:
        def get_redirect_url(self, target):
            # ok: python.open-redirect
            return target


# A function named like a class-based view's handler (get, post, ...) that takes (self, request,
# ...) is taken for one also outside a class: its parameters after request count as URL arguments.
def get(self, request, target):
    # todook: python.open-redirect
    return django_redirect(target)


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
    moved = RedirectResponse(str(request.url.replace(path="/dashboard/" + tab)))
    # ruleid: python.open-redirect
    elsewhere = RedirectResponse(str(request.url.replace(netloc=tab)))
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


# Starlette and FastAPI middleware see every request path, also "//evil.example/".
class TrailingSlashMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not request.url.path.endswith("/"):
            # ruleid: python.open-redirect
            return RedirectResponse(request.url.path + "/")
        if request.url.path != request.url.path.lower():
            # ok: python.open-redirect
            return RedirectResponse(str(request.url.replace(path=request.url.path.lower())))
        if request.url.scheme == "http":
            # ok: python.open-redirect
            return RedirectResponse(str(request.url.replace(scheme="https")))
        if request.url.path.startswith("/go/"):
            # ruleid: python.open-redirect
            return RedirectResponse(str(request.url.replace(netloc=request.url.path.lstrip("/"))))
        if request.url.path.endswith("/") and request.url.path != "/":
            # ruleid: python.open-redirect
            return RedirectResponse(request.url.path[:-1])
        path = request.url.path
        if path.endswith("/index"):
            # ruleid: python.open-redirect
            return RedirectResponse(path[:-6])
        if "next" in request.query_params:
            # ruleid: python.open-redirect
            return RedirectResponse(request.query_params["next"])
        # A Starlette request is a mapping of its ASGI scope: request["path"] is its path.
        if request["path"].startswith("/old/"):
            # ruleid: python.open-redirect
            return RedirectResponse(request["path"][4:])
        if request.url.path.startswith("/account/"):
            # ok: python.open-redirect
            return RedirectResponse(str(request.url_for("login")) + "?next=" + request.url.path)
        return await call_next(request)


@api.middleware("http")
async def lowercase_paths(request: Request, call_next):
    if request.url.path != request.url.path.lower():
        # ruleid: python.open-redirect
        return RedirectResponse(url=request.url.path.lower())
    return await call_next(request)


class AsgiSlashMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and not scope["path"].endswith("/"):
            # ruleid: python.open-redirect
            response = RedirectResponse(scope["path"] + "/")
            await response(scope, receive, send)
            return
        if scope["type"] == "http" and scope["path"].endswith("//"):
            # ruleid: python.open-redirect
            response = RedirectResponse(scope["path"][:-1])
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)



# A callable class with three parameters is not an ASGI middleware by that alone: only its first
# parameter's "path" item counts there, not the attributes of a Starlette request.
class EventHandler:
    def __call__(self, event, context, extra):
        # ok: python.open-redirect
        return RedirectResponse(event.headers["Location"])


# FastAPI and Starlette: a Location header on a Response parameter, a response made in place or
# in middleware.
@api.get("/moved")
async def fa_moved(response: FastAPIResponse, to: str = "/"):
    response.status_code = 307
    # ruleid: python.open-redirect
    response.headers["Location"] = to
    return {}


@api.get("/moved-html")
async def fa_moved_html(to: str = "/"):
    resp = HTMLResponse("<p>moved</p>", status_code=303)
    # ruleid: python.open-redirect
    resp.headers["location"] = to
    return resp


@api.get("/moved-init")
async def fa_moved_init(to: str = "/"):
    # ruleid: python.open-redirect
    a = FastAPIResponse(status_code=307, headers={"location": to})
    # ok: python.open-redirect
    return FastAPIResponse(status_code=307, headers={"location": "/home", "x-to": to})


class LocationRewriteMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if response.status_code in (301, 302) and request.url.path.startswith("/r/"):
            # ruleid: python.open-redirect
            response.headers["location"] = request.url.path.removeprefix("/r")
        return response
