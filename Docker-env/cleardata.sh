#!/bin/bash

rm -rf data/fuzz_workdir/*
rm -rf data/kernels/*
rm -rf data/fuzz_cfgs_dir/
cp -r fuzz_cfgs_dir data/fuzz_cfgs_dir