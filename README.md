# TFW metrics

[![Repository size](https://img.shields.io/github/repo-size/tfw-org/tfw-metrics?label=Repository%20size&color=blue)](https://github.com/tfw-org/tfw-metrics)

This repository collects historical metrics from TFW's ClusterFuzzLite runs. It is separate from the `tfw` library and `tfw-fuzzing` corpus/report repository.

## What is collected

- `metrics/batch_fuzzers.csv`: one row per dynamically discovered fuzzer per successful batch run, with libFuzzer metrics and run/commit metadata.
- `metrics/corpus_snapshots.csv`: timestamped observations of persistent corpus size, keyed to the exact `tfw-fuzzing` `main` commit. Corpus size is not retroactively attached to old batch runs.
- `metrics/coverage_snapshots.csv`: timestamped observations of JaCoCo reports published on `gh-pages`, including that branch's commit and a report fingerprint. Reports are not attributed to unrelated workflow runs.
- `metrics/processed-runs.txt`: batch run IDs and attempts successfully parsed, so failed downloads or parse attempts remain retryable.

Fuzzer and corpus directories are discovered dynamically; no fixed fuzzer count is assumed. CSV inserts are idempotent by their stable run/snapshot keys.

## GitHub Actions setup

Create a repository secret named `TFW_ORG_READ_TOKEN`. Use a fine-grained token with read access to Actions in `tfw-org/tfw` and read access to repository contents in `tfw-org/tfw-fuzzing`. Do not grant write access to those repositories. The workflow's built-in `GITHUB_TOKEN` writes metrics only to this repository.

The scheduled workflow paginates through completed TFW Actions runs, processes successful batch runs oldest first, and records corpus and published-coverage snapshots independently on each scheduled or manual collection. Failed log downloads and parse failures are logged and left unprocessed for a later retry.

## Interpreting the data

`cov` and `ft` are libFuzzer metrics, not source-code coverage percentages. Use `coverage_snapshots.csv` for JaCoCo line/branch coverage. Compare each fuzzer with its own previous runs, and interpret corpus size alongside coverage rather than as a success metric by itself.

## Dashboard

The historical metrics dashboard is published with GitHub Pages. It summarizes successful batch-fuzzer samples, shows selectable per-fuzzer histories for libFuzzer `cov`, `ft`, and execution rate, and charts independent persistent-corpus and JaCoCo coverage snapshots. The dashboard is generated from the CSV files on `metrics-data`; generated site files are not committed to that branch.

After merging the dashboard workflow, enable **Settings → Pages → Build and deployment → GitHub Actions** if Pages is not already configured for Actions. Run **Build and publish metrics dashboard** from the Actions tab to publish the first version. The deployed URL is shown in the workflow's `github-pages` environment and is normally `https://tfw-org.github.io/tfw-metrics/`.

Coverage and corpus charts will become more useful as additional independent snapshots accumulate. In particular, one coverage snapshot is not yet a trend.
