import asyncio
import json
import os
import shlex
import shutil
import subprocess
import sys
from os import system
from typing import Annotated

from django.http import HttpResponse
from django.views import View
from fastapi import Depends, FastAPI, Path, Query, Request
from flask import Flask, request
from pydantic import BaseModel

app = Flask(__name__)
api = FastAPI()

# Allow-lists: the request only picks a key; the program and its arguments are constants.
TOOLS = {"uptime": "uptime", "disk": "df -h"}
REPORTS = {
    # One fixed argument vector per report.
    "disk": ["df", "-h"],
    "memory": ("free", "-m"),  # a tuple works the same
}
SCRIPTS = {"backup": r"tar czf /backups/site.tgz /srv/site"}
DEFAULT_REPORT = ["uptime"]
BACKUP_COMMAND = "tar czf /backups/site.tgz /srv/site"
# Changed later by a view, so not an allow-list.
HOOKS = {"build": "make"}


def make_argv(directory):
    return ["du", "-sh", directory]


class Archive:
    def __init__(self, target):
        self.argv = ["tar", "czf", "/backups/out.tgz", target]


# Flask: request data in a command that a shell runs (os.system, os.popen, shell=True, the
# getoutput() family).
@app.route("/ping")
def ping():
    host = request.args.get("host")
    # ruleid: python.command-injection
    os.system("ping -c 1 " + host)
    # ruleid: python.command-injection
    system(f"traceroute {host}")
    # ruleid: python.command-injection
    out = os.popen(f"nslookup {request.args['name']}").read()
    # ruleid: python.command-injection
    subprocess.run("convert %s out.png" % request.form["file"], shell=True)
    # ruleid: python.command-injection
    subprocess.call("tar czf {}.tgz /srv".format(request.values["name"]), shell=True)
    grep = "grep " + request.args["q"] + " /var/log/app.log"
    # ruleid: python.command-injection
    subprocess.check_output(grep, shell=True)
    # ruleid: python.command-injection
    subprocess.Popen(["ls -l " + request.args["dir"]], shell=True)
    # ruleid: python.command-injection
    subprocess.check_call(args="du -sh " + request.args["dir"], shell=True)
    # ruleid: python.command-injection
    subprocess.getoutput("whois " + request.args["domain"])
    # ruleid: python.command-injection
    subprocess.getstatusoutput(f"dig {request.headers['X-Host']}")
    # ruleid: python.command-injection
    subprocess.run(" ".join(["echo", request.cookies["theme"]]), shell=True)
    use_shell = request.args.get("mode") == "shell"
    # ruleid: python.command-injection
    subprocess.run("ping -c 1 " + host, shell=use_shell)
    return out


# Flask: a shell program run with an argument list. For POSIX shells only the element after -c is
# shell code (the next ones are $0, $1, ...); for cmd /c and PowerShell -Command every element
# after the flag is part of the command.
@app.route("/shells")
def shells():
    cmd = request.args["cmd"]
    # ruleid: python.command-injection
    subprocess.run(["sh", "-c", "echo " + request.cookies["theme"]])
    # ruleid: python.command-injection
    subprocess.run(["/bin/bash", "-lc", cmd], check=True)
    # ruleid: python.command-injection
    subprocess.Popen(("zsh", "-c", cmd))
    # ruleid: python.command-injection
    subprocess.run(["cmd", "/c", "dir", request.args["dir"]])
    # ruleid: python.command-injection
    subprocess.run(["powershell.exe", "-NoProfile", "-Command", "Get-Item", request.args["path"]])
    # ruleid: python.command-injection
    subprocess.run(["pwsh", "-c", cmd])
    # ruleid: python.command-injection
    subprocess.run(["sudo", "-u", "www-data", "sh", "-c", cmd])
    # ok: python.command-injection
    subprocess.run(["sh", "-c", 'tar czf "/backups/$1.tgz" "$1"', "sh", request.args["dir"]])
    # ok: python.command-injection
    subprocess.run(["bash", "/opt/scripts/backup.sh", request.args["dir"]])
    # ok: python.command-injection
    subprocess.run(["sh", "-c", "uptime"])
    return "ok"


# Flask: request data chooses the program (the first element of the argument list, a string
# program without a shell, executable=, or a whole argument vector sent by the client).
@app.route("/run")
def run_program():
    prog = request.args["prog"]
    # ruleid: python.command-injection
    subprocess.run([request.args["prog"], "--version"])
    # ruleid: python.command-injection
    subprocess.run((prog, "-h"))
    # ruleid: python.command-injection
    subprocess.run([prog] + ["--help"])
    # ruleid: python.command-injection
    subprocess.run(request.args["prog"])
    # ruleid: python.command-injection
    subprocess.call(prog)
    # ruleid: python.command-injection
    subprocess.Popen(f"/opt/tools/{request.args['tool']}")
    # ruleid: python.command-injection
    subprocess.run(os.path.join("/opt/tools", request.args["tool"]))
    # ruleid: python.command-injection
    subprocess.run(["true"], executable=request.args["exe"])
    # ruleid: python.command-injection
    subprocess.run(request.args.getlist("argv"))
    # ruleid: python.command-injection
    subprocess.run(request.args["cmd"].split())
    # ruleid: python.command-injection
    subprocess.check_output(shlex.split(request.form["cmd"]))
    line = request.form["line"]
    # ruleid: python.command-injection
    subprocess.run(shlex.split(line))
    # ruleid: python.command-injection
    subprocess.run(line.split(" "))
    return "ok"


@app.post("/jobs")
def jobs():
    body = request.get_json()
    # ruleid: python.command-injection
    subprocess.run(body["program"])
    # ruleid: python.command-injection
    subprocess.run(body["argv"], check=True)
    runner = body.get("runner", "true").strip()
    # ruleid: python.command-injection
    subprocess.Popen(runner)
    # ruleid: python.command-injection
    subprocess.run(args=body.get("tool"))
    # ok: python.command-injection
    subprocess.run(["tar", "czf", "/backups/out.tgz", body["target"]])
    return "ok"


@app.route("/tools/<tool>")
def tool_page(tool):
    # ruleid: python.command-injection
    subprocess.run(tool)
    # ruleid: python.command-injection
    os.system(tool + " --version")
    # ok: python.command-injection
    subprocess.run(["man", tool])
    return "ok"


# Flask: an argument vector sent by the client, unpacked into asyncio.create_subprocess_exec().
@app.route("/async-run")
async def async_run():
    # ruleid: python.command-injection
    await asyncio.create_subprocess_exec(*request.args.getlist("argv"))
    line = request.args["line"]
    # ruleid: python.command-injection
    await asyncio.create_subprocess_exec(*shlex.split(line))
    argv = request.form.getlist("argv")
    # ruleid: python.command-injection
    await asyncio.create_subprocess_exec(*argv)
    body = request.get_json()
    # ruleid: python.command-injection
    await asyncio.create_subprocess_exec(*body["argv"])
    parts = ["ls", "-l", line]
    # ok: python.command-injection
    await asyncio.create_subprocess_exec(*parts)
    # ok: python.command-injection
    await asyncio.create_subprocess_exec(*REPORTS[request.args["r"]])
    return "ok"


# Flask: a fixed program with request data only as arguments, in every container form.
@app.route("/list")
def list_dir():
    directory = request.args["dir"]
    # ok: python.command-injection
    subprocess.run(["ls", "-l", directory])
    # ok: python.command-injection
    subprocess.run(("ls", "-l", request.args["dir"]))
    # ok: python.command-injection
    subprocess.run(["ls", "-l"] + request.args.getlist("d"))
    # ok: python.command-injection
    subprocess.run(["grep", "--"] + [request.args["q"], "/var/log/app.log"])
    argv = ["du", "-sh", directory]
    # ok: python.command-injection
    subprocess.run(argv)
    # ok: python.command-injection
    subprocess.run(make_argv(directory))
    # ok: python.command-injection
    subprocess.run(list(("ls", directory)))
    # ok: python.command-injection
    subprocess.run(args=["ls", directory], check=True)
    # ok: python.command-injection
    subprocess.run(["git", "log", "--", request.args["path"]], shell=False)
    # ok: python.command-injection
    subprocess.run([sys.executable, "-m", "pip", "show", request.args["pkg"]])
    # ok: python.command-injection
    subprocess.run([shutil.which("git"), "log", request.args["ref"]])
    archive = Archive(request.args["dir"])
    # ok: python.command-injection
    subprocess.run(archive.argv)
    base = ["rsync", "-a"]
    # ok: python.command-injection
    subprocess.run(base + [directory, "/backups/"])
    words = ("echo " + request.args["text"]).split()
    # ok: python.command-injection
    subprocess.run(words)
    return "ok"


# Flask: escaping, conversions, constants and request data in a harmless position.
@app.route("/safe")
def safe():
    host = request.args["host"]
    # ok: python.command-injection
    subprocess.run("ping -c 1 " + shlex.quote(host), shell=True)
    # ok: python.command-injection
    os.system(shlex.join(["ping", "-c", "1", host]))
    # ok: python.command-injection
    os.system("sleep %d" % int(request.args["s"]))
    # ok: python.command-injection
    os.system(BACKUP_COMMAND)
    # ok: python.command-injection
    subprocess.run(["sort"], input=request.get_data(), capture_output=True)
    # ok: python.command-injection
    subprocess.run(["env"], env={"GREETING": request.args["greeting"]})
    # ok: python.command-injection
    subprocess.run("uptime", shell=True, timeout=float(request.args["t"]))
    report = "df -h" if request.args.get("r") == "disk" else "uptime"
    # ok: python.command-injection
    os.system(report)
    return "ok"


# Flask: allow-lists (a lookup in a module-level dict of constants, also of argument lists).
@app.route("/report/<name>")
def report(name):
    # ok: python.command-injection
    subprocess.run(TOOLS[name], shell=True)
    # ok: python.command-injection
    os.system(TOOLS.get(name, "uptime"))
    # ok: python.command-injection
    subprocess.run(REPORTS[name])
    # ok: python.command-injection
    subprocess.run(REPORTS.get(name, ["true"]))
    argv = REPORTS.get(name, REPORTS["disk"])
    # ok: python.command-injection
    subprocess.run(argv)
    # ok: python.command-injection
    subprocess.run(REPORTS.get(name, DEFAULT_REPORT))
    # ok: python.command-injection
    subprocess.run(SCRIPTS[name], shell=True)
    # ok: python.command-injection
    subprocess.run(REPORTS.get(name, ["true"]), shell=True)
    # ok: python.command-injection
    os.system(" ".join(REPORTS[name]))
    # ruleid: python.command-injection
    os.system(TOOLS.get(name, request.args["fallback"]))
    # ruleid: python.command-injection
    os.system(HOOKS[name])
    LOCAL_TOOLS = {"x": request.args["tool"]}
    # ruleid: python.command-injection
    os.system(LOCAL_TOOLS["x"])
    return "ok"


@app.post("/hooks")
def add_hook():
    HOOKS[request.form["name"]] = request.form["command"]
    return "ok"


# Look-alikes: methods named run/system/popen of other objects.
class Scheduler:
    def run(self, job, shell=False):
        return job


scheduler = Scheduler()


@app.route("/lookalikes")
def lookalikes():
    # ok: python.command-injection
    scheduler.run(request.args["job"], shell=True)
    # ok: python.command-injection
    archive_store.popen(request.args["name"])
    # ok: python.command-injection
    subprocess_log.info("command %s", request.args["cmd"])
    return "ok"


archive_store = None
subprocess_log = None


# Known limits.
# A membership check against an allow-list is not recognised.
@app.route("/check")
def check():
    tool = request.args["tool"]
    if tool not in ("uptime", "df"):
        return "bad", 400
    # todook: python.command-injection
    os.system(tool)
    return "ok"


# A slice of request data: OpenGrep does not carry taint through a slice, so the rule takes a
# slice of a request value (in place or through a variable) or of a view parameter as request
# data itself. A slice of a value built from request data is missed.
@app.route("/short")
def short():
    # ruleid: python.command-injection
    os.system(request.args["cmd"][:100])
    cmd = request.args["cmd"]
    # ruleid: python.command-injection
    subprocess.run(cmd[:100], shell=True)
    # todoruleid: python.command-injection
    os.system(("echo " + request.args["cmd"])[:100])
    return "ok"


# shell=True with a list: on POSIX the later elements are the shell's own arguments ($0, $1);
# on Windows the list is joined into one command line for cmd.exe, so they are shell code there.
@app.route("/win")
def win():
    # todoruleid: python.command-injection
    subprocess.run(["dir", request.args["dir"]], shell=True)
    # shlex.quote() escapes for POSIX shells only, not for cmd.exe.
    # todoruleid: python.command-injection
    subprocess.run(["cmd", "/c", "type " + shlex.quote(request.args["file"])])
    return "ok"


# An argument list for a shell program built before the call is not followed.
@app.route("/shell-list")
def shell_list():
    argv = ["sh", "-c", request.args["cmd"]]
    # todoruleid: python.command-injection
    subprocess.run(argv)
    return "ok"


# A program built from names only (no string literal, no request value in place) is missed.
TOOL_DIR = "/opt/tools/"


@app.route("/tool-dir")
def tool_dir():
    path = TOOL_DIR + request.args["tool"]
    # todoruleid: python.command-injection
    subprocess.run(path)
    return "ok"


# os.exec*() and os.spawn*() are not covered.
@app.route("/exec")
def exec_program():
    # todoruleid: python.command-injection
    os.execvp(request.args["prog"], ["prog"])


# With a shell, a helper's argument list is taken for a command string.
@app.route("/helper-shell")
def helper_shell():
    # todook: python.command-injection
    subprocess.run(make_argv(request.args["dir"]), shell=True)
    return "ok"


# A variable that held request data and then an argument list with a fixed program.
@app.route("/rebound")
def rebound():
    cmd = request.args["cmd"]
    cmd = ["echo", cmd]
    # todook: python.command-injection
    subprocess.run(cmd)
    return "ok"


# Flask typed converter: the rule cannot see that <int:n> is an int.
@app.route("/sleep/<int:n>")
def sleep(n):
    # todook: python.command-injection
    os.system("sleep %s" % n)
    return "ok"


# A Flask view parameter annotated int is not a source, although Flask passes a str for a <name>
# rule without a converter.
@app.route("/legacy/<legacy_cmd>")
def legacy(legacy_cmd: int):
    # todoruleid: python.command-injection
    os.system("echo %s" % legacy_cmd)
    return "ok"


# Django: GET, POST, body, headers, URL arguments, class-based views.
def django_convert(request):
    # ruleid: python.command-injection
    os.system("convert " + request.GET["file"] + " out.png")
    # ok: python.command-injection
    subprocess.run(["convert", request.GET["file"], "out.png"])
    return HttpResponse("ok")


def django_zip(request, slug):
    # ruleid: python.command-injection
    subprocess.run(f"zip -r {slug}.zip {slug}", shell=True)
    # ok: python.command-injection
    subprocess.run(["zip", "-r", slug + ".zip", slug])
    return HttpResponse("ok")


def django_job(request):
    payload = json.loads(request.body)
    # ruleid: python.command-injection
    subprocess.run(payload["cmd"])
    viewer = payload.get("viewer")
    # ruleid: python.command-injection
    subprocess.Popen(viewer)
    # ruleid: python.command-injection
    os.popen("file " + request.headers["X-Upload"])
    # ok: python.command-injection
    subprocess.run(["file", payload["upload"]])
    return HttpResponse("ok")


class GitView(View):
    def get(self, request, ref):
        # ruleid: python.command-injection
        subprocess.check_output("git show " + self.kwargs["ref"], shell=True)
        # ruleid: python.command-injection
        subprocess.run("git log " + ref, shell=True)
        # ok: python.command-injection
        subprocess.check_output(["git", "show", ref])
        return HttpResponse("ok")

    def post(self, request):
        # ruleid: python.command-injection
        os.popen("ping -c 1 " + self.request.POST["host"])
        return HttpResponse("ok")


# path("sleep/<int:pk>/", views.django_sleep): the converter is in urls.py.
def django_sleep(request, pk):
    # todook: python.command-injection
    os.system("sleep %s" % pk)
    return HttpResponse("ok")


# A default value: Django passes the URL value when the pattern captures one.
def django_default(request, seconds="1"):
    # todook: python.command-injection
    os.system("sleep " + seconds)
    return HttpResponse("ok")


# Helpers whose first parameter is named request look like views: other parameters count as URL
# arguments, and an outgoing request (an HTTP client's) has its headers taken as request data.
def run_for(request, command):
    # todook: python.command-injection
    return os.system(command)


def log_agent(request):
    # todook: python.command-injection
    return os.system("logger " + request.headers["User-Agent"])


# FastAPI: query and path parameters, body models, the Request object; asyncio subprocesses.
class Job(BaseModel):
    script: str
    argv: list[str]
    target: str


class Settings(BaseModel):
    backup_command: str = "tar czf /backups/site.tgz /srv/site"


def get_settings():
    return Settings()


SettingsDep = Annotated[Settings, Depends(get_settings)]


class Protocol(asyncio.SubprocessProtocol):
    pass


@api.get("/ping/{host}")
async def api_ping(host: str, count: int = 1):
    # ruleid: python.command-injection
    os.system("ping -c 1 " + host)
    # ok: python.command-injection
    os.system("ping -c %s localhost" % count)
    # ruleid: python.command-injection
    await asyncio.create_subprocess_shell("ping -c 1 " + host)
    # ok: python.command-injection
    await asyncio.create_subprocess_exec("ping", "-c", "1", host)
    # ok: python.command-injection
    await asyncio.create_subprocess_shell("ping -c 1 " + shlex.quote(host))
    # ruleid: python.command-injection
    await asyncio.create_subprocess_exec(host, "-c", "1")
    # ruleid: python.command-injection
    await asyncio.create_subprocess_exec("sh", "-c", "ping " + host)
    # ruleid: python.command-injection
    await asyncio.create_subprocess_exec(*shlex.split(host))
    # ok: python.command-injection
    await asyncio.create_subprocess_exec(*["ping", "-c", "1", host])
    loop = asyncio.get_running_loop()
    # ruleid: python.command-injection
    await loop.subprocess_shell(Protocol, "ping -c 1 " + host)
    # ok: python.command-injection
    await loop.subprocess_exec(Protocol, "ping", "-c", "1", host)
    # ruleid: python.command-injection
    await loop.subprocess_exec(Protocol, host)
    return {"ok": True}


@api.post("/jobs/{job_id}")
async def api_job(job_id: str, job: Job, request: Request):
    # ruleid: python.command-injection
    subprocess.run(job.script)
    script = job.script
    # ruleid: python.command-injection
    subprocess.run(script)
    # ruleid: python.command-injection
    subprocess.run(job.argv)
    # ruleid: python.command-injection
    subprocess.run("run-job " + job_id, shell=True)
    # ok: python.command-injection
    subprocess.run(["tar", "czf", "/backups/out.tgz", job.target])
    command = (await request.body()).decode()
    # ruleid: python.command-injection
    await asyncio.create_subprocess_shell(command)
    return {"ok": True}


@api.get("/backup/{level}")
async def api_backup(
    level: Annotated[int, Path()],
    settings: SettingsDep,
    other: Annotated[Settings, Depends(get_settings)],
    legacy: Settings = Depends(get_settings),
    cmd: Annotated[str, Query()] = "",
    argv: list[str] = Query(default=[]),
):
    # ok: python.command-injection
    os.system("nice -n %d tar czf /backups/a.tgz /srv" % level)
    # ok: python.command-injection
    subprocess.run(settings.backup_command, shell=True)
    # ok: python.command-injection
    subprocess.run(other.backup_command, shell=True)
    # ok: python.command-injection
    subprocess.run(legacy.backup_command, shell=True)
    # ruleid: python.command-injection
    os.system(cmd)
    # ruleid: python.command-injection
    subprocess.run(argv)
    return {"ok": True}
