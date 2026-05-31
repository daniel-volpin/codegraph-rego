# Failed Full-Population Detection Run

- Started: `2026-05-31T12:28:46Z`
- Elapsed seconds: `8`
- Exit code: `1`
- Command: `OWASP_BENCHMARK_ROOT=/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/BenchmarkJava NEO4J_PASS=password .venv/bin/python run_benchmark_eval.py --config configs/benchmark/multicat_all_available.json --mapping configs/benchmark/policy_registry.json --output-dir outputs/thesis_full_population_detection_2026-05-31 --reset-neo4j`

## Log Tail

```text
Traceback (most recent call last):
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/run_benchmark_eval.py", line 371, in <module>
    raise SystemExit(main())
                     ~~~~^^
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/run_benchmark_eval.py", line 217, in main
    eval_result = ingest_and_evaluate_subset(
        java_root=workspace.java_root,
        reset_neo4j=args.reset_neo4j,
        logger=LOGGER,
    )
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/codegraph/evaluation/pipeline.py", line 137, in ingest_and_evaluate_subset
    clear_graph()
    ~~~~~~~~~~~^^
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/codegraph/evaluation/pipeline.py", line 61, in clear_graph
    session.run("MATCH (n) DETACH DELETE n").consume()
    ~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/.venv/lib/python3.14/site-packages/neo4j/_sync/work/session.py", line 305, in run
    self._connect(self._config.default_access_mode)
    ~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/.venv/lib/python3.14/site-packages/neo4j/_sync/work/session.py", line 126, in _connect
    super()._connect(
    ~~~~~~~~~~~~~~~~^
        access_mode, auth=self._config.auth, **acquire_kwargs
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/.venv/lib/python3.14/site-packages/neo4j/_sync/work/workspace.py", line 181, in _connect
    self._connection = self._pool.acquire(**acquire_kwargs_)
                       ~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/.venv/lib/python3.14/site-packages/neo4j/_sync/io/_pool.py", line 678, in acquire
    return self._acquire(
           ~~~~~~~~~~~~~^
        self.address, auth, deadline, liveness_check_timeout, unprepared
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/.venv/lib/python3.14/site-packages/neo4j/_sync/io/_pool.py", line 418, in _acquire
    return connection_creator()
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/.venv/lib/python3.14/site-packages/neo4j/_sync/io/_pool.py", line 231, in connection_creator
    connection = self.opener(
        address, auth or self.pool_config.auth, deadline
    )
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/.venv/lib/python3.14/site-packages/neo4j/_sync/io/_pool.py", line 638, in opener
    return Bolt.open(
           ~~~~~~~~~^
        addr,
        ^^^^^
    ...<3 lines>...
        pool_config=pool_config,
        ^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/.venv/lib/python3.14/site-packages/neo4j/_sync/io/_bolt.py", line 425, in open
    connection.hello()
    ~~~~~~~~~~~~~~~~^^
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/.venv/lib/python3.14/site-packages/neo4j/_sync/io/_bolt5.py", line 735, in hello
    self.fetch_all()
    ~~~~~~~~~~~~~~^^
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/.venv/lib/python3.14/site-packages/neo4j/_sync/io/_bolt.py", line 882, in fetch_all
    detail_delta, summary_delta = self.fetch_message()
                                  ~~~~~~~~~~~~~~~~~~^^
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/.venv/lib/python3.14/site-packages/neo4j/_sync/io/_bolt.py", line 867, in fetch_message
    res = self._process_message(tag, fields)
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/.venv/lib/python3.14/site-packages/neo4j/_sync/io/_bolt5.py", line 1202, in _process_message
    response.on_failure(summary_metadata or {})
    ~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^
  File "/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/.venv/lib/python3.14/site-packages/neo4j/_sync/io/_common.py", line 304, in on_failure
    raise self._hydrate_error(metadata)
neo4j.exceptions.ClientError: {neo4j_code: Neo.ClientError.Security.AuthenticationRateLimit} {message: The client has provided incorrect authentication details too many times in a row.} {gql_status: 50N42} {gql_status_description: error: general processing exception - unexpected error. Unexpected error has occurred. See debug log for details.}

```

This run did not produce metrics. Neo4j was reachable but authentication failed with the non-secret compose default; do not reset or delete the existing Neo4j volume without explicit user confirmation.
