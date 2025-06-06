#!/usr/bin/env python3

from pathlib import Path
from runner import BenchmarkRunner
from dfri import DFRIPipeline
from single_circuits import SingleCircuitMeasure
from circuits import circuit_names
from sys import argv
from signoz_post import post_results

from argparse import ArgumentParser

def parse_arguments():
    parser = ArgumentParser(prog=argv[0],
                            description="Framework for benchmarking proof producer")

    parser.add_argument("-t", "--trace", required=True, help="path to trace file group")
    parser.add_argument("-b", "--proof-producer-binary", required=True, help="path to proof producer binary")
    parser.add_argument("-o", "--out-dir", default="/tmp", help="directory where run artifacts will be saved")
    parser.add_argument("-m", "--execution_mode", choices=["subprocess", "benchexec"], default="subprocess",
                        help="the mode of execution for the binary. Simple subprocess and benchexec are supported")
    parser.add_argument("-s", "--scenario", choices=(["full", "dfri", "single_circuits"] + circuit_names), default="dfri",
                        help="benchmarking scenario. Supported proving and verification for all the available circuit, plus DFRI pipeline")
    parser.add_argument("-p", "--post-results", action='store_true', help="post results to SigNoz")
    parser.add_argument("-e", "--otlp-endpoint", help="OTLP endpoint address")

    args = parser.parse_args()

    # Check if OTLP endpoint was passed
    if args.post_results and args.otlp_endpoint is None:
        raise ValueError("Posting is requested, but no endpoint was provided")

    return args

def print_results(result_set):
    # TODO: add writing to file in some format suitable for posting
    total_time = 0
    max_memory = 0
    for result in result_set:
        time_str = "Time {:.2f} s".format(result["time"])
        memory_str = "Memory {} KB".format(result["memory"]) if result["memory"] is not None else ""
        print(f"{result['name']}: {time_str} {memory_str}")

        total_time += result["time"]

        if result["memory"] is not None:
            max_memory = max(max_memory, result["memory"])

    print("Total time: {:.2f} s".format(total_time))
    if max_memory != 0:
        print("Peak memory consumption: {:.2f} MB".format(max_memory / 1024))

if __name__ == "__main__":
    args = parse_arguments()
    runner = BenchmarkRunner(execution_mode=args.execution_mode)
    # Create out directory if not exists
    out_dir = Path(args.out_dir)
    out_dir.mkdir(exist_ok=True)

    results = []

    # DFRI part
    if args.scenario == "dfri" or args.scenario == "full":
        dfri = DFRIPipeline(args.proof_producer_binary, args.trace, out_dir)

        dfri_results = runner.run_set(dfri.get_first_stage_commands())
        dfri_results += runner.run_set(dfri.get_second_stage_commands())

        results += dfri_results

    # Single circuits
    if args.scenario != "dfri":
        single_circuits = SingleCircuitMeasure(args.proof_producer_binary, args.trace, out_dir)
        if args.scenario == "single_circuits" or args.scenario == "full":
            single_circuit_results = runner.run_set(single_circuits.make_all_commands())
        else:
            single_circuit_results = runner.run_set(single_circuits.make_circuit_command(args.scenario))
        results += single_circuit_results

    print_results(results)
    if args.post_results:
        post_results(results, args.otlp_endpoint)
