#!/bin/bash

while true; do
    gpustat --json >> gpu_utilization_gpustat_log.json
done
