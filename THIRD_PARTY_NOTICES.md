# Third-Party Notices

The MIT license in [LICENSE](./LICENSE) applies to CodeGraph's original source code and documentation. It does not replace licenses that apply to third-party software or source material represented in research artifacts.

## OWASP Benchmark

CodeGraph evaluates the [OWASP Benchmark for Java](https://github.com/OWASP-Benchmark/BenchmarkJava). The upstream project distributes its source under the [GNU General Public License, version 2](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/master/LICENSE).

Tracked evaluation data under `outputs/thesis_final_*` includes benchmark identifiers and, in some remediation artifacts, source excerpts and generated diffs derived from OWASP Benchmark test cases. Files under `index/` may also contain representations derived from analyzed benchmark or case-study source. The applicable upstream copyrights and license terms remain with that source material.

These artifacts are included to support research review and reproducibility. CodeGraph does not claim ownership of third-party source excerpts.

## Runtime and Development Dependencies

Python, JavaScript, GitHub Actions, OPA, Neo4j, and other dependencies retain their own licenses. Their versions are declared in the repository manifests, lockfiles, and workflow files.
