import io
import os
import pathlib
import shutil
import uuid
import zipfile
from pathlib import Path
from typing import Annotated

from django.conf import settings
from django.http import FileResponse as DjangoFileResponse
from django.http import HttpResponse
from django.views import View
from fastapi import Depends, FastAPI, Query
from fastapi import Path as FastApiPath
from fastapi.responses import FileResponse
from flask import Flask, request, send_file, send_from_directory
from pydantic import BaseModel
from starlette.responses import FileResponse as StarletteFileResponse
from werkzeug.security import safe_join
from werkzeug.utils import secure_filename

app = Flask(__name__)
api = FastAPI()

UPLOAD_FOLDER = "/srv/uploads"
REPORTS = {"daily": "reports/daily.csv", "weekly": "reports/weekly.csv"}
ALLOWED_NAMES = ("readme.txt", "license.txt")
DOWNLOADS = {
    # One fixed file per download name.
    "manual": r"docs\manual.pdf",
    "license": "docs/LICENSE.txt",  # plain text
}
# Changed later by a view, so not an allow-list.
EXPORTS = {"latest": "exports/latest.csv"}


# Flask: query strings, form fields, headers, cookies, uploads, JSON bodies and URL variables.
@app.route("/files")
def read_file():
    name = request.args.get("name")
    # ruleid: python.path-traversal
    with open(os.path.join(UPLOAD_FOLDER, name)) as fh:
        body = fh.read()
    # ruleid: python.path-traversal
    data = open(UPLOAD_FOLDER + "/" + request.args["name"], "rb").read()
    # ruleid: python.path-traversal
    os.remove(f"{UPLOAD_FOLDER}/{request.form['victim']}")
    # ruleid: python.path-traversal
    shutil.rmtree(os.path.join(UPLOAD_FOLDER, request.cookies["workspace"]))
    # ruleid: python.path-traversal
    shutil.copy("template.txt", os.path.join(UPLOAD_FOLDER, request.headers["X-Target"]))
    # ruleid: python.path-traversal
    entries = os.listdir(os.path.join(UPLOAD_FOLDER, request.get_json()["dir"]))
    # ok: python.path-traversal
    with open(os.path.join(UPLOAD_FOLDER, secure_filename(name))) as fh:
        body = fh.read()
    # ok: python.path-traversal
    data = open(os.path.join(UPLOAD_FOLDER, os.path.basename(name)), "rb").read()
    # ok: python.path-traversal
    data = open(os.path.join(UPLOAD_FOLDER, "%d.txt" % int(request.args["id"])), "rb").read()
    # ok: python.path-traversal
    os.remove(os.path.join(UPLOAD_FOLDER, "cache.tmp"))
    report = REPORTS["weekly"] if request.args.get("period") == "weekly" else REPORTS["daily"]
    # ok: python.path-traversal
    data = open(report).read()
    # ok: python.path-traversal
    open(os.path.join(UPLOAD_FOLDER, "notes.txt"), "w").write(request.form["note"])
    return body + str(entries)


@app.route("/download/<path:filename>")
def download(filename):
    # ruleid: python.path-traversal
    return send_file(os.path.join(UPLOAD_FOLDER, filename))


@app.route("/raw/<filename>")
def raw(filename):
    # ok: python.path-traversal
    return send_from_directory(UPLOAD_FOLDER, filename)


@app.route("/shared/<owner>/<filename>")
def shared(owner, filename):
    # ruleid: python.path-traversal
    return send_from_directory(owner, filename)


@app.route("/echo", methods=["POST"])
def echo():
    # ok: python.path-traversal
    return send_file(io.BytesIO(request.get_data()), download_name="echo.bin")


@app.route("/safe/<path:filename>")
def safe(filename):
    target = safe_join(UPLOAD_FOLDER, filename)
    if target is None:
        return "not found", 404
    # ok: python.path-traversal
    return send_file(target)


@app.post("/upload")
def upload():
    file = request.files["file"]
    # ruleid: python.path-traversal
    file.save(os.path.join(UPLOAD_FOLDER, file.filename))
    # ok: python.path-traversal
    file.save(os.path.join(UPLOAD_FOLDER, secure_filename(file.filename)))
    archive = zipfile.ZipFile(file.stream)
    # ok: python.path-traversal
    member = archive.open(request.form["member"]).read()
    # ok: python.path-traversal
    member = (zipfile.Path(archive) / request.form["member"]).read_text()
    # ok: python.path-traversal
    member = zipfile.Path(archive).joinpath(request.form["member"]).read_bytes()
    root = zipfile.Path(archive)
    # A zipfile.Path kept in a variable is taken for a file-system Path.
    # todook: python.path-traversal
    member = (root / request.form["member"]).read_text()
    return member


@app.route("/notes/<slug>")
def notes(slug):
    # ruleid: python.path-traversal
    text = Path("notes", slug).read_text()
    # ruleid: python.path-traversal
    (pathlib.Path(UPLOAD_FOLDER) / request.args["n"]).write_text("x")
    target = Path(UPLOAD_FOLDER) / slug
    # ruleid: python.path-traversal
    target.unlink()
    # ok: python.path-traversal
    text = (Path("notes") / Path(slug).name).read_text()
    # ok: python.path-traversal
    text = Path("notes", "index.md").read_text()
    # The resolved path is checked against the base directory (Python docs, PurePath.is_relative_to).
    checked = (Path(UPLOAD_FOLDER) / slug).resolve()
    if not checked.is_relative_to(UPLOAD_FOLDER):
        return "no", 400
    # todook: python.path-traversal
    return checked.read_text()


# A Path joined in the function from a module constant, a helper or a parameter: the `/`
# operator and joinpath() are pathlib (a str has no `/`).
NOTES_DIR = Path("/srv/notes")


def upload_root():
    return Path(UPLOAD_FOLDER)


def note_path(name):
    return NOTES_DIR / name


@app.route("/under/<name>")
def under(name):
    # ruleid: python.path-traversal
    text = (upload_root() / name).read_text()
    # ruleid: python.path-traversal
    text = (NOTES_DIR / request.args["n"]).read_text()
    stale = NOTES_DIR / name
    # ruleid: python.path-traversal
    stale.unlink()
    # ruleid: python.path-traversal
    text = NOTES_DIR.joinpath("drafts", name).read_bytes()
    # ok: python.path-traversal
    text = (NOTES_DIR / "index.md").read_text()
    # ok: python.path-traversal
    text = (NOTES_DIR / secure_filename(name)).read_text()
    # ok: python.path-traversal
    text = (NOTES_DIR / str(uuid.UUID(request.args["id"]))).read_text()
    # A Path returned whole by a helper is not followed.
    # todoruleid: python.path-traversal
    return note_path(name).read_text() + text


# A slice of request data: OpenGrep does not carry taint through a slice, so the rule takes a
# slice of a request value (in place or through a variable) or of a view parameter as request
# data itself. A slice of a value built from request data is missed.
@app.route("/short")
def short_name():
    # ruleid: python.path-traversal
    data = send_file(request.args["f"][:100])
    name = request.args["f"]
    # ruleid: python.path-traversal
    data = open(name[:100])
    # todoruleid: python.path-traversal
    data = send_file((request.args["f"] + ".txt")[:100])
    return data


# Allow-lists: a lookup in a module-level dict of constants; a membership check is not recognised.
@app.route("/report")
def report():
    # ok: python.path-traversal
    data = send_file(REPORTS.get(request.args.get("period"), REPORTS["daily"]))
    # ruleid: python.path-traversal
    data = send_file(REPORTS.get(request.args["period"], request.args["period"]))
    # ok: python.path-traversal
    data = send_file(DOWNLOADS[request.args["download"]])
    # ruleid: python.path-traversal
    data = send_file(EXPORTS.get(request.args["export"], "exports/latest.csv"))
    CUSTOM = {"mine": request.args["path"]}
    # ruleid: python.path-traversal
    data = send_file(CUSTOM["mine"])
    name = request.args["name"]
    if name not in ALLOWED_NAMES:
        return "no", 404
    # todook: python.path-traversal
    return open(os.path.join(UPLOAD_FOLDER, name)).read()


@app.post("/exports")
def add_export():
    EXPORTS.setdefault(request.form["name"], request.form["path"])
    return "ok"


# Flask typed converter: the rule cannot see that <int:number> is an int.
@app.route("/invoices/<int:number>")
def invoice(number):
    # todook: python.path-traversal
    return send_file(os.path.join(UPLOAD_FOLDER, "invoice-%s.pdf" % number))


# Django: the HttpRequest of a view, URL arguments, and FileResponse with an opened file.
def django_download(request, filename):
    # ruleid: python.path-traversal
    return DjangoFileResponse(open(os.path.join(settings.MEDIA_ROOT, filename), "rb"))


def django_read(request):
    # ruleid: python.path-traversal
    with open(os.path.join(settings.MEDIA_ROOT, request.GET["doc"])) as fh:
        text = fh.read()
    # ruleid: python.path-traversal
    os.unlink(settings.MEDIA_ROOT + "/" + request.POST["doc"])
    # ok: python.path-traversal
    with open(os.path.join(settings.MEDIA_ROOT, os.path.basename(request.GET["doc"]))) as fh:
        text = fh.read()
    # ok: python.path-traversal
    return DjangoFileResponse(open(os.path.join(settings.MEDIA_ROOT, "manual.pdf"), "rb"))


class AttachmentView(View):
    def get(self, request, name):
        # ruleid: python.path-traversal
        shutil.move(os.path.join(settings.MEDIA_ROOT, name), "/tmp/trash")
        # ruleid: python.path-traversal
        return HttpResponse(Path(settings.MEDIA_ROOT, self.request.GET["n"]).read_bytes())


# Django settings: BASE_DIR is a Path in new projects.
def django_notes(request):
    # ruleid: python.path-traversal
    return HttpResponse((settings.BASE_DIR / "notes" / request.GET["f"]).read_text())


# path("docs/<int:pk>/", views.django_doc): the converter is in urls.py.
def django_doc(request, pk):
    # todook: python.path-traversal
    return DjangoFileResponse(open(os.path.join(settings.MEDIA_ROOT, "%s.pdf" % pk), "rb"))


# A default value: Django passes the URL value when the pattern captures one.
def django_page(request, page="index"):
    # todook: python.path-traversal
    return DjangoFileResponse(open(os.path.join(settings.MEDIA_ROOT, page + ".html"), "rb"))


# Helpers whose first parameter is named request look like views: other parameters count as URL
# arguments, and an outgoing request (an HTTP client's) has its headers taken as request data.
def read_template(request, template_name):
    # todook: python.path-traversal
    return open(os.path.join("templates", template_name)).read()


def cache_outgoing(request):
    # todook: python.path-traversal
    return open(os.path.join("/var/cache/out", request.headers["X-Cache-Key"]), "w")


# FastAPI: path and query parameters, bodies; FastAPI/Starlette FileResponse takes a path.
class Export(BaseModel):
    filename: str


@api.get("/static/{name}")
async def static_file(name: str, sub: str = ""):
    # ruleid: python.path-traversal
    return FileResponse(os.path.join("static", name))


@api.get("/docs/{name}")
async def docs_file(name: str, sub: str = ""):
    # ruleid: python.path-traversal
    return FileResponse(path=f"static/{sub}/index.html")


@api.get("/plain/{name}")
async def plain_file(name: str):
    # ok: python.path-traversal
    return FileResponse(os.path.join("static", os.path.basename(name)), filename=name)


@api.post("/export")
async def export(body: Export):
    # ruleid: python.path-traversal
    Path("exports", body.filename).write_text("report")
    # ok: python.path-traversal
    Path("exports", secure_filename(body.filename)).write_text("report")
    return {"ok": True}


@api.get("/starlette/{name}")
async def starlette_file(name: str):
    # ruleid: python.path-traversal
    return StarletteFileResponse(os.path.join("static", name))


class Settings(BaseModel):
    export_dir: str = "exports"


def get_settings():
    return Settings()


# FastAPI's Annotated form, in place or through an alias.
SettingsDep = Annotated[Settings, Depends(get_settings)]


@api.get("/annotated/{number}")
async def annotated(
    number: Annotated[int, FastApiPath()],
    settings: SettingsDep,
    other: Annotated[Settings, Depends(get_settings)],
    name: Annotated[str, Query()] = "index",
):
    # ok: python.path-traversal
    FileResponse(os.path.join(settings.export_dir, other.export_dir, "%d.csv" % number))
    # ruleid: python.path-traversal
    return FileResponse(os.path.join("pages", name + ".html"))


# A Flask view parameter annotated int is no longer a source, although Flask passes a str for a
# <name> rule without a converter.
@app.route("/legacy/<legacy_name>")
def legacy(legacy_name: int):
    # todoruleid: python.path-traversal
    return send_file(os.path.join(UPLOAD_FOLDER, legacy_name))


# FastAPI converts int parameters; Depends() parameters are dependencies, not request data.
@api.get("/pages/{number}")
async def page(number: int, settings: Settings = Depends(get_settings)):
    # ok: python.path-traversal
    return FileResponse(os.path.join("pages", "%d.html" % number))


@api.get("/exports/latest")
async def latest(settings: Settings = Depends(get_settings)):
    # ok: python.path-traversal
    return FileResponse(os.path.join(settings.export_dir, "latest.csv"))
