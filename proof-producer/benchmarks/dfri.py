from pathlib import Path
from circuits import circuit_names, circuit_limits
from runner import BenchmarkRunner

class DFRIArg:
    def __init__(self, arg_name: str, out_dir: Path, file_name=None):
        self.option = f"--{arg_name}"
        self.out_dir = out_dir
        self.circuit_dependent = False
        self.file_name = (file_name if file_name is not None else arg_name)

    def get_option(self):
        return self.option

    def get_value(self):
        return str(self.out_dir / self.file_name)


class DFRICircuitArg(DFRIArg):
    def __init__(self, arg_name, out_dir, file_name=None):
        super().__init__(arg_name, out_dir, file_name)
        self.circuit_dependent = True
        if file_name is None:
            file_name = arg_name

    def get_value(self, circuit):
        return str(self.out_dir / "{}.{}".format(self.file_name, circuit))


class DFRIAggregateArg(DFRIArg):
    def __init__(self, arg_name, arg_factory):
        super().__init__(arg_name, None)
        self.circuit_dependent = False
        self.value = " ".join([arg_factory.get_value(circuit) for circuit in circuit_names])

    def get_value(self):
        return self.value

class DFRIPipeline:

    def __init__(self, binary, trace_file, out_dir):
        self.binary = binary
        self.trace_file = trace_file
        self.initialize_common_args(Path(out_dir))

    def initialize_common_args(self, out_dir):
        # Partial proof out files
        self.assignment_description_arg = DFRICircuitArg("assignment-description-file", out_dir)
        self.proof_arg = DFRICircuitArg("proof", out_dir)
        self.challenge_arg = DFRICircuitArg("challenge", out_dir)
        self.theta_power_arg = DFRICircuitArg("theta-power-file", out_dir)
        self.common_data_arg = DFRICircuitArg("common-data", out_dir)
        self.updated_commitment_state = DFRICircuitArg("updated-commitment-state-file", out_dir, "commitment-state-file")
        self.commitment_state = DFRICircuitArg("commitment-state-file", out_dir)
        # Aggregated challenge args
        self.input_challenges_arg = DFRIAggregateArg("input-challenge-files", self.challenge_arg)
        self.agg_challenge_arg = DFRIArg("aggregated-challenge-file", out_dir)
        # Combined Q args
        self.q_poly_file_arg = DFRICircuitArg("combined-Q-polynomial-file", out_dir)
        # Aggregated FRI args
        self.input_combined_Q = DFRIAggregateArg("input-combined-Q-polynomial-files", self.q_poly_file_arg)
        self.agg_fri_proof_arg = DFRIArg("proof", out_dir, file_name="aggregated_fri_proof")
        self.consistency_check_arg = DFRIArg("consistency-checks-challenges-file", out_dir)
        # Consistency checks args
        self.lpc_proof_arg = DFRICircuitArg("proof", out_dir, "lpc_proof")
        # Merge proof args
        self.input_partial_proof_arg = DFRIAggregateArg("partial-proof", self.proof_arg)
        self.input_initial_proof_arg = DFRIAggregateArg("initial-proof", self.lpc_proof_arg)
        self.agg_fri_proof = DFRIArg("aggregated-FRI-proof", out_dir, file_name="aggregated_fri_proof")
        self.merged_proof_arg = DFRIArg("proof", out_dir, "final_proof")


    def make_circuit_command(self, name, stage, args, init_options=[]):
        result_commands = []
        common_cmd_prefix = [self.binary] + ["--stage", stage] + init_options + circuit_limits
        for circuit in circuit_names:
            current_cmd = common_cmd_prefix.copy() + ["--circuit-name", circuit]
            for arg in args:
                current_cmd.append(arg.get_option())
                if arg.circuit_dependent:
                    current_cmd.append(arg.get_value(circuit))
                else:
                    current_cmd.append(arg.get_value())
            result_commands.append({
                "name" : f"{name} {circuit}",
                "args": current_cmd,
                })
        return result_commands

    def make_aggregate_command(self, name, stage, args, init_options=[]):
        result_cmd = [self.binary] + ["--stage", stage] + init_options + circuit_limits
        for arg in args:
            result_cmd.append(arg.get_option())
            if arg.circuit_dependent:
                # Only assignment description is allowed as circuit-dependent argument here,
                # since assignment tables for all circuit must have same descriptions
                assert arg.get_option() == "--assignment-description-file"
                result_cmd.append(arg.get_value(circuit_names[0]))
            else:
                result_cmd += arg.get_value().split(" ")
        return {
            "name" : name,
            "args" : result_cmd,
        }

    def make_partial_proof_commands(self):
        partial_proof_args = [
            self.proof_arg,
            self.assignment_description_arg,
            self.challenge_arg,
            self.theta_power_arg,
            self.common_data_arg,
            self.updated_commitment_state
        ]
        trace_arg = ["--trace", self.trace_file]
        return self.make_circuit_command("Partial proof", "fast-generate-partial-proof", partial_proof_args, init_options=trace_arg)

    def make_aggregated_challenge_command(self):
        agg_challenge_args = [self.input_challenges_arg, self.agg_challenge_arg]
        return self.make_aggregate_command("Aggregated challenge", "generate-aggregated-challenge", agg_challenge_args)

    def make_combined_q_commands(self):
        class StartingPowerArg:
            def __init__(self, theta_power_arg):
                self.circuit_dependent = True
                self.theta_arg = theta_power_arg

            def get_option(self):
                return "--combined-Q-starting-power"

            def get_value(self, circuit):
                starting_power = 0
                for circuit_iter in circuit_names:
                    if circuit == circuit_iter:
                        break
                    file_name = self.theta_arg.get_value(circuit_iter)
                    with open(file_name) as theta_file:
                        starting_power += int(theta_file.readlines()[0])
                return str(starting_power)

        combined_q_args = [
            self.commitment_state,
            self.agg_challenge_arg,
            self.q_poly_file_arg,
            StartingPowerArg(self.theta_power_arg)
        ]
        return self.make_circuit_command("Combined Q", "compute-combined-Q", combined_q_args)

    def make_aggregate_fri_command(self):
        agg_fri_args = [
            self.assignment_description_arg,
            self.agg_challenge_arg,
            self.input_combined_Q,
            self.consistency_check_arg,
            self.agg_fri_proof_arg
        ]
        unused_artifact = ["--proof-of-work-file", "/dev/null"]
        return self.make_aggregate_command("Aggregate FRI", "aggregated-FRI", agg_fri_args, unused_artifact)

    def make_consistency_check_commands(self):
        lpc_challenge_args = [
            self.commitment_state,
            self.q_poly_file_arg,
            self.consistency_check_arg,
            self.lpc_proof_arg
        ]
        return self.make_circuit_command("Consistency check challenges", "consistency-checks", lpc_challenge_args)

    def make_merge_proof_command(self):
        merge_proof_args = [
            self.input_partial_proof_arg,
            self.input_initial_proof_arg,
            self.agg_fri_proof,
            self.merged_proof_arg
        ]
        return self.make_aggregate_command("Merge proofs", "merge-proofs", merge_proof_args)

    def get_first_stage_commands(self):
        return self.make_partial_proof_commands()

    def get_second_stage_commands(self):
        return ([self.make_aggregated_challenge_command()]
                + self.make_combined_q_commands()
                + [self.make_aggregate_fri_command()]
                + self.make_consistency_check_commands()
                + [self.make_merge_proof_command()])
