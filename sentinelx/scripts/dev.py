import argparse
import os
import secrets
import socket
import subprocess
import sys
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path


def free_port(start):
    for port in range(start, start + 100):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No available local port")


def main():
    parser = argparse.ArgumentParser(description="Run SentinelX locally; random session keys never printed")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--execute", action="store_true", help="Explicitly enable live API remediation")
    parser.add_argument("--audit-only", action="store_true", help="Disable demo execution")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    api_port, ui_port = free_port(8000), free_port(8501)
    environment = os.environ.copy()
    environment["SENTINELX_MODE"] = "live" if args.live else "demo"
    environment["SENTINELX_REMEDIATION_ENABLED"] = str(args.execute if args.live else not args.audit_only).lower()
    for role in ("reader", "operator", "approver"):
        name = f"SENTINELX_{role.upper()}_KEY"
        if not args.live:
            environment[name] = secrets.token_urlsafe(36)
        elif not environment.get(name):
            raise SystemExit("Live mode requires configured role keys")
    environment["SENTINELX_API_URL"] = f"http://127.0.0.1:{api_port}"
    dashboard_env = {key: value for key, value in environment.items()
                     if not key.startswith(("AWS_", "DATABRICKS_", "SENTINELX_CONFIG"))}
    if args.live:
        for role in ("operator", "approver"):
            dashboard_env.pop(f"SENTINELX_{role.upper()}_KEY", None)
    dashboard_env.update(DEMO_MODE="false", LIVE_MODE="true")  # local stack: dashboard reads the API started below
    print(f"SentinelX dashboard: http://127.0.0.1:{ui_port}", flush=True)
    print(f"Authenticated API: http://127.0.0.1:{api_port} / mode: {environment['SENTINELX_MODE']}", flush=True)
    processes = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        try:
            processes.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "backend.api.app:create_app", "--factory",
                             "--host", "127.0.0.1", "--port", str(api_port), "--no-access-log"], cwd=root, env=environment))
            processes.append(subprocess.Popen([sys.executable, "-m", "streamlit", "run", "dashboard/app.py", "--server.address",
                             "127.0.0.1", "--server.port", str(ui_port)], cwd=root, env=dashboard_env))
            wait([pool.submit(process.wait) for process in processes], return_when=FIRST_COMPLETED)
        except KeyboardInterrupt:
            pass
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()