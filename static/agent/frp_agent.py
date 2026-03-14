#!/usr/bin/env python3
import json
import os
import platform
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request


AGENT_VERSION = "0.1.0"


def env_text(name, default=""):
    return str(os.environ.get(name, default)).strip()


def env_int(name, default):
    raw = env_text(name, "")
    if not raw:
        return int(default)
    try:
        return int(raw)
    except ValueError:
        return int(default)


MANAGER_URL = env_text("MANAGER_URL")
NODE_ID = env_text("NODE_ID")
NODE_TOKEN = env_text("NODE_TOKEN")
POLL_INTERVAL = max(2, env_int("POLL_INTERVAL", 5))
REQUEST_TIMEOUT = max(3, env_int("REQUEST_TIMEOUT", 15))
COMMAND_TIMEOUT = max(3, env_int("COMMAND_TIMEOUT", 20))
MAX_COMMAND_LENGTH = max(64, env_int("MAX_COMMAND_LENGTH", 1024))
ALLOW_UNSAFE_COMMANDS = env_text("ALLOW_UNSAFE_COMMANDS", "0") == "1"
DEFAULT_ALLOWED_PREFIXES = ["systemctl", "service", "pgrep", "pkill", "echo", "nohup"]
ALLOWED_COMMAND_PREFIXES = [item.strip() for item in env_text("ALLOWED_COMMAND_PREFIXES", ",".join(DEFAULT_ALLOWED_PREFIXES)).split(",") if item.strip()]


def check_env():
    missing = []
    if not MANAGER_URL:
        missing.append("MANAGER_URL")
    if not NODE_ID:
        missing.append("NODE_ID")
    if not NODE_TOKEN:
        missing.append("NODE_TOKEN")
    if missing:
        raise RuntimeError("Missing env: " + ", ".join(missing))


def build_url(path):
    return MANAGER_URL.rstrip("/") + path


def request_json(path, payload):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=build_url(path),
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {NODE_TOKEN}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def safe_tail(text, max_len=4000):
    data = str(text or "")
    if len(data) <= max_len:
        return data
    return data[-max_len:]


def local_facts():
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "agent_version": AGENT_VERSION,
    }


def register_once():
    payload = {"node_id": NODE_ID}
    payload.update(local_facts())
    return request_json("/api/agent/v1/register", payload)


def pull_jobs():
    payload = {"node_id": NODE_ID, "lease_seconds": 45}
    payload.update(local_facts())
    data = request_json("/api/agent/v1/pull", payload)
    jobs = data.get("jobs", [])
    poll_after = data.get("poll_after_sec", POLL_INTERVAL)
    try:
        poll_after = int(poll_after)
    except (TypeError, ValueError):
        poll_after = POLL_INTERVAL
    return jobs if isinstance(jobs, list) else [], max(2, poll_after)


def report_runtime(runtime_id, kind, name, state, metadata=None, enabled=True):
    payload = {
        "node_id": NODE_ID,
        "runtime": {
            "id": runtime_id,
            "kind": kind,
            "name": name,
            "status": state,
            "enabled": bool(enabled),
            "metadata": metadata if isinstance(metadata, dict) else {},
        },
    }
    return request_json("/api/agent/v1/runtime/report", payload)


def mark_running(job_id, lease_id):
    payload = {"node_id": NODE_ID, "lease_id": lease_id}
    return request_json(f"/api/agent/v1/jobs/{job_id}/start", payload)


def complete_job(job_id, lease_id, success, result=None, error=""):
    payload = {
        "node_id": NODE_ID,
        "lease_id": lease_id,
        "success": bool(success),
        "result": result if isinstance(result, dict) else {},
        "error": str(error or ""),
    }
    return request_json(f"/api/agent/v1/jobs/{job_id}/complete", payload)


def run_shell(command):
    cmd = str(command or "").strip()
    if not cmd:
        return {"exit_code": 2, "stdout": "", "stderr": "empty command"}

    if len(cmd) > MAX_COMMAND_LENGTH:
        return {"exit_code": 2, "stdout": "", "stderr": "command too long"}
    if "\n" in cmd or "\r" in cmd or "\x00" in cmd:
        return {"exit_code": 2, "stdout": "", "stderr": "invalid command characters"}

    if not ALLOW_UNSAFE_COMMANDS and ALLOWED_COMMAND_PREFIXES:
        first_word = cmd.split(" ", 1)[0].strip().lower()
        allow = {item.lower() for item in ALLOWED_COMMAND_PREFIXES}
        if first_word not in allow:
            return {"exit_code": 2, "stdout": "", "stderr": f"command prefix not allowed: {first_word}"}

    if os.name == "nt":
        try:
            proc = subprocess.run(["cmd", "/c", cmd], capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {"exit_code": 124, "stdout": "", "stderr": "command timeout"}
    else:
        try:
            proc = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {"exit_code": 124, "stdout": "", "stderr": "command timeout"}
    return {
        "exit_code": int(proc.returncode),
        "stdout": safe_tail(proc.stdout),
        "stderr": safe_tail(proc.stderr),
    }


def execute_instance_job(job_type, payload):
    runtime_id = str(payload.get("runtime_id", "")).strip()
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    name = str(payload.get("name", "")).strip() or runtime_id or "instance"
    kind = str(payload.get("kind", "")).strip() or "frpc"

    if not runtime_id:
        raise RuntimeError("runtime_id is required")

    start_cmd = str(metadata.get("start_command", "")).strip()
    stop_cmd = str(metadata.get("stop_command", "")).strip()
    check_cmd = str(metadata.get("check_command", "")).strip()

    if job_type == "instance.ensure_running":
        if not start_cmd:
            raise RuntimeError("start_command is required")
        output = run_shell(start_cmd)
        success = output["exit_code"] == 0
        state = "running" if success else "error"
    elif job_type == "instance.ensure_stopped":
        if not stop_cmd:
            raise RuntimeError("stop_command is required")
        output = run_shell(stop_cmd)
        success = output["exit_code"] == 0
        state = "stopped" if success else "error"
    else:
        raise RuntimeError(f"unsupported job type: {job_type}")

    if check_cmd:
        check = run_shell(check_cmd)
        if check["exit_code"] == 0:
            state = "running"
        elif state != "error":
            state = "stopped"
        output["check_stdout"] = check["stdout"]
        output["check_stderr"] = check["stderr"]
        output["check_exit_code"] = check["exit_code"]

    report_runtime(runtime_id, kind, name, state, metadata=metadata, enabled=state != "stopped")
    result = {
        "message": state,
        "exit_code": output.get("exit_code", 0),
        "stdout_tail": output.get("stdout", ""),
        "stderr_tail": output.get("stderr", ""),
    }
    return success, result


def process_job(job):
    if not isinstance(job, dict):
        return

    job_id = str(job.get("id", "")).strip()
    lease_id = str(job.get("lease_id", "")).strip()
    job_type = str(job.get("type", "")).strip()
    payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}

    if not job_id or not lease_id:
        return

    try:
        mark_running(job_id, lease_id)
    except Exception:
        return

    try:
        if job_type in {"instance.ensure_running", "instance.ensure_stopped"}:
            success, result = execute_instance_job(job_type, payload)
            complete_job(job_id, lease_id, success=success, result=result, error="" if success else str(result.get("stderr_tail", "")))
            return

        complete_job(
            job_id,
            lease_id,
            success=False,
            result={"message": "unsupported job type"},
            error=f"unsupported job type: {job_type}",
        )
    except Exception as exc:
        complete_job(
            job_id,
            lease_id,
            success=False,
            result={"message": "job execution failed"},
            error=str(exc),
        )


def main_loop():
    backoff = POLL_INTERVAL
    while True:
        try:
            jobs, poll_after = pull_jobs()
            for job in jobs:
                process_job(job)
            backoff = poll_after
            time.sleep(backoff)
        except urllib.error.HTTPError as exc:
            sys.stderr.write(f"agent http error: {exc.code}\n")
            time.sleep(min(30, backoff + 2))
            backoff = min(30, backoff + 2)
        except urllib.error.URLError as exc:
            sys.stderr.write(f"agent network error: {exc.reason}\n")
            time.sleep(min(30, backoff + 2))
            backoff = min(30, backoff + 2)
        except Exception as exc:
            sys.stderr.write(f"agent loop error: {exc}\n")
            time.sleep(min(30, backoff + 2))
            backoff = min(30, backoff + 2)


def main():
    check_env()
    register_once()
    main_loop()


if __name__ == "__main__":
    main()
