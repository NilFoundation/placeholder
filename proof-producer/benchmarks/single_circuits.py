from pathlib import Path
from circuits import circuit_names, circuit_limits

class SingleCircuitMeasure:
    def __init__(self, binary, trace_file, out_dir):
        self.binary = binary
        self.trace_file = trace_file
        self.out_dir = Path(out_dir)

    def make_assignment_command(self, circuit):
        assignment_command = [
            self.binary, "--stage", "fill-assignment",
            "--circuit-name", circuit,
            "--circuit", str(self.out_dir / "circuit.{}".format(circuit)),
            "--trace", self.trace_file,
            "--assignment-table", str(self.out_dir / "assignment.{}".format(circuit)),
            "--assignment-description-file", str(self.out_dir / "assignment_description.{}".format(circuit)),
            ] + circuit_limits
        return {
            "name" : f"make-assignment-{circuit}",
            "args" : assignment_command,
        }

    def make_prove_verify_command(self, circuit):
        prove_verify_command = [
            self.binary, "--stage", "all",
            "--circuit-name", circuit,
            "--circuit", str(self.out_dir / "circuit.{}".format(circuit)),
            "--assignment-table", str(self.out_dir / "assignment.{}".format(circuit)),
            "--assignment-description-file", str(self.out_dir / "assignment_description.{}".format(circuit)),
            # Suppress writing output files
            "--commitment-state-file", "/dev/null", "--preprocessed-data", "/dev/null", "--common-data", "/dev/null", "-p", "/dev/null", "-j", "/dev/null",
            ]
        return {
            "name" : f"prove-verify-{circuit}",
            "args" : prove_verify_command
        }

    def make_all_commands(self):
        result_set = []
        for circuit in circuit_names:
            result_set += self.make_circuit_command(circuit)
        return result_set

    def make_circuit_command(self, circuit):
        return [self.make_assignment_command(circuit), self.make_prove_verify_command(circuit)]
