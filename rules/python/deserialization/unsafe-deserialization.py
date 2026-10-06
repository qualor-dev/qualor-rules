import base64
import io
import json
import marshal
import os
import pickle
import shelve
from typing import Annotated

import dill
import jsonpickle
import yaml
from django.http import HttpResponse, JsonResponse
from django.views import View
from fastapi import Body, Depends, FastAPI, File, Path, Request, UploadFile
from flask import Flask, request
from pydantic import BaseModel

app = Flask(__name__)
api = FastAPI()

CACHE_DIR = "/var/cache/reports"
SAMPLES = {
    # Fixed sample documents, one per kind.
    "list": "[a, b]",
    "map": "{a: 1}",
}
# Strings with escapes are literals too.
MULTILINE_SAMPLES = {"list": "- a\n- b", "quoted": "title: \"x\""}
# A nested table is not recognised as an allow-list.
NESTED_SAMPLES = {"list": {"short": "[a]"}}
EMPTY_PICKLES = {"list": [128, 4, 93, 148, 46], "dict": (128, 4, 125, 148, 46)}
# Changed later by a view, so not an allow-list.
PRESETS = {"default": "a: 1"}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        raise pickle.UnpicklingError("global '%s.%s' is forbidden" % (module, name))


# Flask: request bodies, uploaded files, cookies, headers, form fields, URL variables.
@app.post("/import")
def import_state():
    # ruleid: python.unsafe-deserialization
    state = pickle.loads(request.data)
    # ruleid: python.unsafe-deserialization
    upload = pickle.load(request.files["state"])
    blob = request.files["state"].read()
    # ruleid: python.unsafe-deserialization
    again = pickle.Unpickler(io.BytesIO(blob)).load()
    # ruleid: python.unsafe-deserialization
    prefs = pickle.loads(base64.b64decode(request.cookies["prefs"]))
    # ruleid: python.unsafe-deserialization
    ctx = pickle.loads(bytes.fromhex(request.headers["X-Context"]))
    # ruleid: python.unsafe-deserialization
    code = marshal.loads(request.get_data())
    return "ok"


@app.post("/config")
def load_config():
    text = request.form["config"]
    # ruleid: python.unsafe-deserialization
    cfg = yaml.load(text, Loader=yaml.Loader)
    # ruleid: python.unsafe-deserialization
    cfg2 = yaml.load(text, yaml.UnsafeLoader)
    # ruleid: python.unsafe-deserialization
    cfg3 = yaml.unsafe_load(request.get_json()["yaml"])
    # ruleid: python.unsafe-deserialization
    cfg4 = yaml.full_load(text)
    # ruleid: python.unsafe-deserialization
    docs = list(yaml.load_all(text, Loader=yaml.FullLoader))
    # ruleid: python.unsafe-deserialization
    cfg5 = yaml.load(text)
    # ruleid: python.unsafe-deserialization
    cfg6 = yaml.load(f"defaults: 1\n{text}", Loader=yaml.CLoader)
    return "ok"


@app.route("/restore/<token>")
def restore(token):
    # ruleid: python.unsafe-deserialization
    obj = jsonpickle.decode(base64.urlsafe_b64decode(token))
    # ruleid: python.unsafe-deserialization
    fn = dill.loads(request.files["job"].read())
    # The request names the shelf to load: a true finding when the name can reach an uploaded
    # file.
    # ruleid: python.unsafe-deserialization
    with shelve.open(request.args["db"]) as db:
        keys = list(db.keys())
    return str(keys)


# Flask: safe loaders and formats, data in a harmless position, constants and allow-lists.
@app.post("/config-safe")
def load_config_safe():
    text = request.form["config"]
    # ok: python.unsafe-deserialization
    a = yaml.safe_load(text)
    # ok: python.unsafe-deserialization
    b = yaml.load(text, Loader=yaml.SafeLoader)
    # ok: python.unsafe-deserialization
    c = yaml.load(text, yaml.CSafeLoader)
    # ok: python.unsafe-deserialization
    d = list(yaml.safe_load_all(text))
    # ok: python.unsafe-deserialization
    e = yaml.load(text, Loader=yaml.BaseLoader)
    # ok: python.unsafe-deserialization
    f = json.loads(request.data)
    # ok: python.unsafe-deserialization
    g = RestrictedUnpickler(io.BytesIO(request.data)).load()
    # Request data is serialised, not loaded.
    # ok: python.unsafe-deserialization
    h = pickle.dumps(request.get_json())
    # ok: python.unsafe-deserialization
    i = yaml.dump(request.get_json())
    # ok: python.unsafe-deserialization
    j = jsonpickle.encode(request.get_json())
    return "ok"


@app.route("/sample/<kind>")
def sample(kind):
    # ok: python.unsafe-deserialization
    doc = yaml.load(SAMPLES.get(kind, SAMPLES["list"]), Loader=yaml.Loader)
    # ok: python.unsafe-deserialization
    empty = pickle.loads(bytes(EMPTY_PICKLES[kind]))
    # The request picks the encoding of a server-side pickle, not its content.
    with open(os.path.join(CACHE_DIR, "report.pickle"), "rb") as fh:
        # ok: python.unsafe-deserialization
        report = pickle.load(fh, encoding=request.args.get("enc", "ASCII"))
    # ruleid: python.unsafe-deserialization
    preset = yaml.load(PRESETS.get(kind, "a: 1"), Loader=yaml.Loader)
    # ok: python.unsafe-deserialization
    multi = yaml.load(MULTILINE_SAMPLES[kind], Loader=yaml.Loader)
    # todook: python.unsafe-deserialization
    nested = yaml.load(NESTED_SAMPLES[kind]["short"], Loader=yaml.Loader)
    FALLBACK_DOC = request.args["doc"]
    # ruleid: python.unsafe-deserialization
    local = yaml.load(SAMPLES.get(kind, FALLBACK_DOC), Loader=yaml.Loader)
    # A round trip through the serialiser is a deep copy, not a load of request data.
    # ok: python.unsafe-deserialization
    copy = pickle.loads(pickle.dumps(request.get_json()))
    # ruleid: python.unsafe-deserialization
    streamed = yaml.load(stream=request.data, Loader=yaml.Loader)
    return str((doc, empty, report, preset, multi, nested, local, copy, streamed))


@app.route("/sample2/<kind>")
def sample2(kind):
    # ruleid: python.unsafe-deserialization
    doc = yaml.load(SAMPLES.get(kind, request.args["doc"]), Loader=yaml.Loader)
    # ruleid: python.unsafe-deserialization
    preset = yaml.load(PRESETS[kind], Loader=yaml.Loader)
    return str((doc, preset))


@app.post("/presets")
def add_preset():
    PRESETS[request.form["name"]] = request.form["yaml"]
    return "ok"


# Look-alikes: other libraries' loads()/load() and a custom loader built on SafeLoader.
class IncludeLoader(yaml.SafeLoader):
    pass


@app.post("/lookalikes")
def lookalikes():
    store = json
    # ok: python.unsafe-deserialization
    a = store.loads(request.data)
    # ok: python.unsafe-deserialization
    b = yaml.load(request.data, Loader=IncludeLoader)
    return str((a, b))


# A file chosen by a request name: a true finding when the name can reach an uploaded file (as
# for shelve.open above).
@app.route("/cached/<name>")
def cached(name):
    path = os.path.join(CACHE_DIR, os.path.basename(name) + ".pickle")
    with open(path, "rb") as fh:
        # ruleid: python.unsafe-deserialization
        return str(pickle.load(fh))


# A signature check before loading is not recognised.
@app.post("/signed")
def signed():
    import hmac

    data = request.get_data()
    expected = hmac.new(b"server-key", data, "sha256").hexdigest()
    if not hmac.compare_digest(request.headers["X-Signature"], expected):
        return "bad signature", 400
    # todook: python.unsafe-deserialization
    return str(pickle.loads(data))


# A slice of request data: OpenGrep does not carry taint through a slice, so the rule takes a
# slice of a request value (in place or through a variable) or of a view parameter as request
# data itself. A slice of a value built from request data is missed.
@app.post("/framed")
def framed():
    data = request.get_data()
    # ruleid: python.unsafe-deserialization
    pickle.loads(data[4:])
    # todoruleid: python.unsafe-deserialization
    pickle.loads((request.get_data() + b".")[4:])
    # ruleid: python.unsafe-deserialization
    return str(pickle.loads(request.get_data()[4:]))


# A custom loader class built on an unsafe loader is not followed.
class LegacyLoader(yaml.UnsafeLoader):
    pass


@app.post("/legacy")
def legacy():
    # todoruleid: python.unsafe-deserialization
    return str(yaml.load(request.data, Loader=LegacyLoader))


# Flask typed converter: the rule cannot see that <int:n> is an int.
@app.route("/slot/<int:slot>")
def slot(slot):
    # todook: python.unsafe-deserialization
    return str(marshal.loads(bytes([slot])))


# A membership check against an allow-list is not recognised.
@app.route("/kind")
def kind():
    k = request.args["k"]
    if k not in ("list", "map"):
        return "bad", 400
    # todook: python.unsafe-deserialization
    return str(yaml.load(k, Loader=yaml.Loader))


# A Flask view parameter annotated int is not a source, although Flask passes a str for a
# <name> rule without a converter.
@app.route("/legacy-state/<state>")
def legacy_state(state: int):
    # todoruleid: python.unsafe-deserialization
    return str(pickle.loads(base64.b64decode(state)))


# Django: request.body, FILES, COOKIES, META, POST, URL arguments, class-based views.
def django_import(request):
    # ruleid: python.unsafe-deserialization
    state = pickle.loads(request.body)
    # ruleid: python.unsafe-deserialization
    upload = pickle.load(request.FILES["state"])
    # ruleid: python.unsafe-deserialization
    prefs = pickle.loads(base64.b64decode(request.COOKIES["prefs"]))
    # ruleid: python.unsafe-deserialization
    meta = yaml.load(request.META["HTTP_X_META"], Loader=yaml.Loader)
    # ok: python.unsafe-deserialization
    safe = yaml.safe_load(request.POST["config"])
    # ok: python.unsafe-deserialization
    data = json.loads(request.body)
    return JsonResponse({"ok": True})


def django_restore(request, token):
    # ruleid: python.unsafe-deserialization
    obj = jsonpickle.decode(base64.b64decode(token))
    return HttpResponse(str(obj))


class ImportView(View):
    def post(self, request):
        # ruleid: python.unsafe-deserialization
        state = dill.loads(self.request.body)
        # ruleid: python.unsafe-deserialization
        config = yaml.unsafe_load(self.request.POST["config"])
        return JsonResponse({"ok": True})


# path("slots/<int:pk>/", views.django_slot): the converter is in urls.py.
def django_slot(request, pk):
    # todook: python.unsafe-deserialization
    return HttpResponse(str(marshal.loads(bytes([pk]))))


# A default value: Django passes the URL value when the pattern captures one.
def django_preset(request, preset="a: 1"):
    # todook: python.unsafe-deserialization
    return HttpResponse(str(yaml.load(preset, Loader=yaml.Loader)))


# Helpers whose first parameter is named request look like views: other parameters count as URL
# arguments, and an outgoing request (an HTTP client's) has its headers taken as request data.
def decode_blob(request, blob):
    # todook: python.unsafe-deserialization
    return pickle.loads(blob)


def decode_header(request):
    # todook: python.unsafe-deserialization
    return pickle.loads(base64.b64decode(request.headers["X-State"]))


# FastAPI: uploaded files, bodies, the Request object, path and query parameters.
class Job(BaseModel):
    name: str
    payload: str


@api.post("/jobs/{job_id}")
async def create_job(job_id: str, job: Job, file: UploadFile, request: Request):
    # ruleid: python.unsafe-deserialization
    a = pickle.loads(await file.read())
    # ruleid: python.unsafe-deserialization
    b = pickle.loads(base64.b64decode(job.payload))
    # ruleid: python.unsafe-deserialization
    c = pickle.loads(await request.body())
    # ruleid: python.unsafe-deserialization
    d = yaml.load(job_id, Loader=yaml.Loader)
    # ok: python.unsafe-deserialization
    e = yaml.safe_load(job.payload)
    return {"ok": True}


@api.post("/raw")
async def raw(data: Annotated[bytes, Body()], other: bytes = File()):
    # ruleid: python.unsafe-deserialization
    a = pickle.loads(data)
    # ruleid: python.unsafe-deserialization
    b = marshal.loads(other)
    return {"ok": True}


class Settings(BaseModel):
    state_file: str = "/var/lib/app/state.pickle"


def get_settings():
    return Settings()


SettingsDep = Annotated[Settings, Depends(get_settings)]


@api.get("/state/{slot}")
async def state(
    slot: Annotated[int, Path()],
    settings: SettingsDep,
    other: Annotated[Settings, Depends(get_settings)],
    legacy: Settings = Depends(get_settings),
):
    # ok: python.unsafe-deserialization
    with shelve.open(settings.state_file) as db:
        value = db.get(str(slot))
    # ok: python.unsafe-deserialization
    with shelve.open(other.state_file) as db2:
        value2 = db2.get(str(slot))
    # ok: python.unsafe-deserialization
    with shelve.open(legacy.state_file) as db3:
        value3 = db3.get(str(slot))
    # ok: python.unsafe-deserialization
    code = marshal.loads(bytes([slot]))
    return {"value": value}
