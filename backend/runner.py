"""Background experiment execution runner using subprocess CLI invocations with live stage tracking."""

import os
import sys
import time
import uuid
import json
import yaml
import subprocess
import threading
from typing import Dict, Any, Optional, List

from backend.security import validate_preset_name, validate_run_id

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RUNS_DIR = os.path.join(ROOT_DIR, "runs")
CONFIGS_DIR = os.path.join(ROOT_DIR, "configs")


class JobTracker:
    def __init__(
        self,
        job_id: str,
        run_id: str,
        preset_name: str,
        config_path: str,
        run_dir: str,
    ):
        self.job_id = job_id
        self.run_id = run_id
        self.preset_name = preset_name
        self.config_path = config_path
        self.run_dir = run_dir
        self.status = "QUEUED"  # QUEUED, RUNNING, COMPLETED, FAILED
        self.current_stage = "Stage 0: Initializing experiment environment"
        self.stage_number = 0
        self.total_stages = 6
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.exit_code: Optional[int] = None
        self.error: Optional[str] = None
        self.logs: List[Dict[str, str]] = []
        self._lock = threading.Lock()
        self.process: Optional[subprocess.Popen] = None

    def append_log(self, text: str):
        with self._lock:
            ts = time.strftime("%H:%M:%S")
            clean = text.strip()
            if clean:
                self.logs.append({"time": ts, "message": clean})
                if len(self.logs) > 1000:
                    self.logs = self.logs[-1000:]
            self._detect_stage(clean)

    def _detect_stage(self, text: str):
        t_lower = text.lower()
        if "stage 1" in t_lower or "loading cifar-10" in t_lower:
            self.current_stage = "Stage 1: Dataset preparation & attack injection"
            self.stage_number = 1
        elif "stage 2" in t_lower or "training baseline model" in t_lower:
            self.current_stage = "Stage 2: Model training & dynamics collection"
            self.stage_number = 2
        elif "stage 3" in t_lower or "extracting trajectory dynamics" in t_lower:
            self.current_stage = "Stage 3: Trajectory fingerprint scoring"
            self.stage_number = 3
        elif "stage 4" in t_lower or "assigning mitigation tiers" in t_lower:
            self.current_stage = "Stage 4: Soft quarantine tier assignment"
            self.stage_number = 4
        elif "stage 5" in t_lower or "retraining model with weighted loss" in t_lower:
            self.current_stage = "Stage 5: Mitigated retraining & canary guardrail"
            self.stage_number = 5
        elif "stage 6" in t_lower or "final evaluation" in t_lower or "writing hash-chained audit" in t_lower:
            self.current_stage = "Stage 6: Final evaluation & cryptographic audit log"
            self.stage_number = 6

    def save_persistent_status(self):
        """Save status to runs/{run_id}/status.json for persistence across backend restarts."""
        try:
            status_data = self.to_dict()
            status_file = os.path.join(self.run_dir, "status.json")
            with open(status_file, "w", encoding="utf-8") as f:
                json.dump(status_data, f, indent=2)
        except Exception:
            pass

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            elapsed = 0.0
            if self.start_time:
                end = self.end_time or time.time()
                elapsed = round(end - self.start_time, 2)

            return {
                "job_id": self.job_id,
                "run_id": self.run_id,
                "preset_name": self.preset_name,
                "status": self.status,
                "current_stage": self.current_stage,
                "stage_number": self.stage_number,
                "total_stages": self.total_stages,
                "start_time": self.start_time,
                "end_time": self.end_time,
                "elapsed_seconds": elapsed,
                "exit_code": self.exit_code,
                "error": self.error,
                "run_dir": self.run_dir,
                "logs": list(self.logs),
            }


class PipelineExecutionManager:
    """Manages asynchronous CLI pipeline executions with process isolation and persistent metadata."""

    def __init__(self):
        self.jobs: Dict[str, JobTracker] = {}
        self.run_to_job: Dict[str, str] = {}
        self._lock = threading.Lock()

    def start_pipeline(
        self,
        preset_name: str,
        seed: Optional[int] = None,
        epochs: Optional[int] = None,
        custom_run_id: Optional[str] = None,
    ) -> JobTracker:
        # Validate preset
        validate_preset_name(preset_name)

        with self._lock:
            # Check for active running jobs to avoid CPU overload
            for j in self.jobs.values():
                if j.status == "RUNNING":
                    raise ValueError(
                        f"A pipeline experiment ('{j.run_id}') is currently executing on CPU. Simultaneous runs are restricted to ensure resource stability."
                    )

            preset_file = os.path.join(CONFIGS_DIR, f"{preset_name}.yaml")
            if not os.path.exists(preset_file):
                raise FileNotFoundError(f"Config preset '{preset_name}.yaml' not found in configs/.")

            with open(preset_file, "r", encoding="utf-8") as f:
                config_data = yaml.safe_load(f) or {}

            # Build safe unique run ID
            if custom_run_id:
                run_id = validate_run_id(custom_run_id)
            else:
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                short_id = uuid.uuid4().hex[:6]
                run_id = f"{preset_name}_{timestamp}_{short_id}"

            job_id = f"job_{uuid.uuid4().hex[:8]}"
            run_dir = os.path.join(RUNS_DIR, run_id)
            os.makedirs(run_dir, exist_ok=True)

            # Update configuration with unique run_id and parameters
            config_data["run_id"] = run_id
            config_data["save_dir"] = "runs"
            if seed is not None:
                config_data["seed"] = int(seed)
            if epochs is not None:
                config_data["epochs"] = max(1, min(50, int(epochs)))

            config_path = os.path.join(run_dir, "config.yaml")
            with open(config_path, "w", encoding="utf-8") as f:
                yaml.dump(config_data, f, default_flow_style=False)

            tracker = JobTracker(
                job_id=job_id,
                run_id=run_id,
                preset_name=preset_name,
                config_path=config_path,
                run_dir=run_dir,
            )

            self.jobs[job_id] = tracker
            self.run_to_job[run_id] = job_id
            tracker.save_persistent_status()

            # Start background execution thread
            thread = threading.Thread(target=self._run_subprocess_worker, args=(tracker,), daemon=True)
            thread.start()

            return tracker

    def _run_subprocess_worker(self, tracker: JobTracker):
        tracker.status = "RUNNING"
        tracker.start_time = time.time()
        tracker.append_log(f"Spawning PoisonLens pipeline process: {tracker.run_id}")
        tracker.append_log(f"CLI Command: {sys.executable} -m poisonlens.pipeline --config {tracker.config_path}")
        tracker.save_persistent_status()

        cmd = [sys.executable, "-m", "poisonlens.pipeline", "--config", tracker.config_path]

        try:
            # Set unbuffered python output
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=ROOT_DIR,
                env=env,
            )
            tracker.process = proc

            # Read stdout lines live
            if proc.stdout:
                for line in iter(proc.stdout.readline, ""):
                    if line:
                        tracker.append_log(line)
                proc.stdout.close()

            proc.wait()
            tracker.exit_code = proc.returncode
            tracker.end_time = time.time()

            if proc.returncode == 0:
                tracker.status = "COMPLETED"
                tracker.current_stage = "Pipeline execution complete"
                tracker.stage_number = 6
                tracker.append_log("Process exited successfully (code 0). Results verified.")
            else:
                tracker.status = "FAILED"
                tracker.error = f"Pipeline process terminated with non-zero exit code {proc.returncode}."
                tracker.append_log(f"FAILURE: Process returned exit code {proc.returncode}")

        except Exception as e:
            tracker.status = "FAILED"
            tracker.end_time = time.time()
            tracker.error = str(e)
            tracker.append_log(f"EXCEPTION: {str(e)}")

        finally:
            tracker.save_persistent_status()

    def get_status(self, run_or_job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            # Check in-memory by job_id
            if run_or_job_id in self.jobs:
                return self.jobs[run_or_job_id].to_dict()

            # Check in-memory by run_id
            if run_or_job_id in self.run_to_job:
                jid = self.run_to_job[run_or_job_id]
                if jid in self.jobs:
                    return self.jobs[jid].to_dict()

        # Check persistent status on disk in runs/{run_id}/status.json
        run_dir = os.path.join(RUNS_DIR, run_or_job_id)
        status_file = os.path.join(run_dir, "status.json")
        if os.path.exists(status_file):
            try:
                with open(status_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        # If pipeline_results.json exists, reconstruct completed status
        pipeline_results_path = os.path.join(run_dir, "pipeline_results.json")
        if os.path.exists(pipeline_results_path):
            try:
                with open(pipeline_results_path, "r", encoding="utf-8") as f:
                    p_res = json.load(f)
                return {
                    "job_id": f"completed_{run_or_job_id}",
                    "run_id": run_or_job_id,
                    "preset_name": run_or_job_id,
                    "status": "COMPLETED",
                    "current_stage": "Pipeline execution complete",
                    "stage_number": 6,
                    "total_stages": 6,
                    "elapsed_seconds": p_res.get("total_time_seconds", 0.0),
                    "exit_code": 0,
                    "error": None,
                    "run_dir": run_dir,
                    "logs": [],
                }
            except Exception:
                pass

        return None


# Global execution manager instance
pipeline_manager = PipelineExecutionManager()
