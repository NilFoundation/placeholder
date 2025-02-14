from pathlib import Path
import subprocess
import time
from benchexec import runexecutor
from tempfile import TemporaryDirectory

class BenchmarkRunner:
    def _subprocess_executor(self, cmd):
        start = time.time_ns()
        p = subprocess.run(cmd["args"], capture_output=True)
        if p.returncode != 0:
            error = p.stderr.decode("utf-8")
            raise RuntimeError("Command failed, stderr: {}".format(error))
        elapsed_ns = time.time_ns() - start
        return {
            "name" : cmd["name"],
            "time": elapsed_ns / 1e9,
            "memory": None,
        }

    def _runexec_executor(self, cmd):
        with TemporaryDirectory() as tempdir:
            args = cmd["args"]
            base_log_name = str(Path(tempdir) / "cmd_output.{}".format(hash("".join(args))))
            stdout_file = base_log_name + ".stdout"
            stderr_file = base_log_name + ".stderr"
            run_result = self.runexec.execute_run(args, stdout_file, error_filename=stderr_file)
            if run_result["returnvalue"] != 0:
                with open(stderr_file) as error:
                    raise RuntimeError("Command failed, stderr: {}".format(error.read()))
            return {
                "name" : cmd["name"],
                "time": run_result["walltime"],
                "memory": run_result["memory"] // 1024 # memory in KB
            }

    def __init__(self, execution_mode="subprocess"):
        if execution_mode == "subprocess":
            self.executor = self._subprocess_executor
        elif execution_mode == "benchexec":
            self.runexec = runexecutor.RunExecutor()
            self.executor = self._runexec_executor
        else:
            raise ValueError("Unknown executor type")

    def run_set(self, commands):
        # TODO: maybe add number of repetitions
        results = []
        for cmd in commands:
            print(f"Running command: {" ".join(cmd["args"])}")
            run_time = self.executor(cmd)
            results.append(run_time)
        return results
