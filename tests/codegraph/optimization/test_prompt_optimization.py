from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

from codegraph.optimization.critic import format_transcript_summary
from codegraph.optimization.dspy_optimizer import (
    DSPyPromptCompiler,
    RemediationTrajectoryDemonstration,
    bootstrap_few_shot_demos_from_results,
)
from codegraph.optimization.evaluator import evaluate_trajectory
from codegraph.optimization.textgrad_optimizer import TextGradPromptOptimizer
from codegraph.remediation.agentic.contracts import (
    AgentRemediationResult,
    AgentToolCall,
    AgentTurn,
    AgentVerificationStatus,
)


class TestOptimizationEvaluatorAndCritic(unittest.TestCase):
    def test_evaluate_successful_trajectory(self) -> None:
        verification = AgentVerificationStatus(
            compile_passed=True,
            compile_output="0 errors",
            tests_passed=True,
            test_output="All tests passed",
            policy_passed=True,
            policy_findings=[],
            remaining_violations=[],
        )
        turns = [
            AgentTurn(role="user", content="Fix vulnerability"),
            AgentTurn(role="assistant", content="Reading", tool_calls=[AgentToolCall("c1", "read_file", {})]),
            AgentTurn(role="assistant", content="Finishing", tool_calls=[AgentToolCall("c2", "finish_remediation", {})]),
        ]
        result = AgentRemediationResult(
            status="SUCCESS",
            rule_id="ISO-A.10-WEAK-HASH",
            method_key="pkg.App#m()",
            target_method="pkg.App.m()",
            workspace_root="/tmp/ws",
            modified_files=["App.java"],
            diff="--- a\n+++ b",
            verification=verification,
            turns=turns,
            reason="Fixed",
            iterations=3,
        )

        score = evaluate_trajectory(result)
        self.assertTrue(score.all_passed)
        self.assertGreater(score.total_score, 0.8)
        self.assertEqual(len(score.diagnostics), 0)

    def test_evaluate_failed_trajectory_with_diagnostics(self) -> None:
        verification = AgentVerificationStatus(
            compile_passed=False,
            compile_output="Syntax error at line 42",
            tests_passed=False,
            test_output=None,
            policy_passed=False,
            policy_findings=[],
            remaining_violations=["ISO-A.8-SQL-INJECTION"],
        )
        result = AgentRemediationResult(
            status="MAX_TURNS_EXCEEDED",
            rule_id="ISO-A.8-SQL-INJECTION",
            method_key="pkg.App#m()",
            target_method="pkg.App.m()",
            workspace_root="/tmp/ws",
            modified_files=[],
            diff="",
            verification=verification,
            turns=[AgentTurn(role="user", content="Fix")],
            reason="Exceeded turns",
            iterations=1,
        )

        score = evaluate_trajectory(result)
        self.assertFalse(score.all_passed)
        self.assertEqual(score.compile_score, 0.0)
        self.assertIn("Compiler Error: Syntax error at line 42", score.diagnostics)
        self.assertIn("Remaining Policy Violations: ISO-A.8-SQL-INJECTION", score.diagnostics)

    def test_format_transcript_summary(self) -> None:
        result = AgentRemediationResult(
            status="SUCCESS",
            rule_id="ISO-A.10-WEAK-HASH",
            method_key="key",
            target_method="target",
            workspace_root="/tmp",
            modified_files=[],
            diff="",
            verification=None,
            turns=[
                AgentTurn(role="assistant", content="read", tool_calls=[AgentToolCall("1", "read_file", {})]),
            ],
            reason="ok",
            iterations=1,
        )
        summary = format_transcript_summary(result)
        self.assertIn("read_file", summary)


class TestTextGradAndDSPyOptimizers(unittest.TestCase):
    def test_textgrad_optimizer_synthesizes_prompt(self) -> None:
        critic_response = '{"root_failure_mode": "missing_params", "textual_gradient": "Use PreparedStatement with parameter binding."}'
        optimizer_response = '{"updated_prompt": "Refined instructions for SQL injection.", "rationale": "Clarified parameter binding."}'

        call_idx = 0

        def mock_llm(*_args, **_kwargs):
            nonlocal call_idx
            call_idx += 1
            content = critic_response if call_idx == 1 else optimizer_response
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
            )

        verification = AgentVerificationStatus(
            compile_passed=True,
            compile_output="",
            tests_passed=True,
            test_output="",
            policy_passed=False,
            policy_findings=[],
            remaining_violations=["ISO-A.8-SQL-INJECTION"],
        )
        result = AgentRemediationResult(
            status="MAX_TURNS_EXCEEDED",
            rule_id="ISO-A.8-SQL-INJECTION",
            method_key="m",
            target_method="target",
            workspace_root="/tmp",
            modified_files=[],
            diff="",
            verification=verification,
            turns=[AgentTurn(role="assistant", content="test", tool_calls=[])],
            reason="failed",
            iterations=1,
        )

        optimizer = TextGradPromptOptimizer(llm_client=mock_llm)
        updated, gradients, rationale = optimizer.optimize_prompt("Base prompt", [result])

        self.assertEqual(updated, "Refined instructions for SQL injection.")
        self.assertEqual(rationale, "Clarified parameter binding.")
        self.assertGreater(len(gradients), 0)

    def test_dspy_prompt_compiler_and_bootstrapper(self) -> None:
        demo = RemediationTrajectoryDemonstration(
            rule_id="ISO-A.10-WEAK-HASH",
            target_method="App.hash()",
            initial_code="MD5",
            tool_sequence=["read_file", "edit_file", "run_verification"],
            final_patch="SHA-256",
            verification_summary="Passed 3 gates.",
        )
        compiler = DSPyPromptCompiler([demo])
        compiled = compiler.compile_instruction_prompt("Base instructions.")

        self.assertIn("Base instructions.", compiled)
        self.assertIn("ISO-A.10-WEAK-HASH", compiled)
        self.assertIn("SHA-256", compiled)

    def test_bootstrap_few_shot_demos_from_results(self) -> None:
        results = [
            {
                "status": "SUCCESS",
                "rule_id": "ISO-A.10-WEAK-HASH",
                "target_method": "App.hash()",
                "diff": "+ SHA-256",
                "turns": [{"tool_calls": [{"name": "edit_file"}]}],
            }
        ]
        demos = bootstrap_few_shot_demos_from_results(results)
        self.assertEqual(len(demos), 1)
        self.assertEqual(demos[0].rule_id, "ISO-A.10-WEAK-HASH")
        self.assertEqual(demos[0].final_patch, "+ SHA-256")


class TestContinuousEvolutionAndTrajectoryBank(unittest.TestCase):
    def test_trajectory_bank_deposit_and_query(self) -> None:
        import tempfile

        from codegraph.optimization.trajectory_bank import TrajectoryBank, TrajectoryBankEntry

        with tempfile.TemporaryDirectory() as tmpdir:
            storage = Path(tmpdir) / "bank.json"
            bank = TrajectoryBank(storage_path=storage)

            entry = TrajectoryBankEntry(
                case_id="case_001",
                rule_id="ISO-A.10-WEAK-HASH",
                target_method="App.hash()",
                initial_code="MD5",
                diff="--- a\n+++ b\n+ SHA-256",
                turns_count=2,
                tool_sequence=["read_file", "edit_file"],
                verification_summary="Passed 3 gates.",
                timestamp="2026-09-19T12:00:00Z",
            )
            bank.deposit(entry)
            bank.save()

            reloaded = TrajectoryBank(storage_path=storage)
            matches = reloaded.query_exemplars("ISO-A.10-WEAK-HASH")
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].case_id, "case_001")
            self.assertIn("SHA-256", matches[0].diff)

    def test_continuous_evolution_engine_epoch(self) -> None:
        import tempfile

        from codegraph.optimization.evolution_loop import ContinuousEvolutionEngine

        critic_response = '{"root_failure_mode": "missing_params", "textual_gradient": "Use PreparedStatement"}'
        optimizer_response = '{"updated_prompt": "Evolved system prompt v1", "rationale": "Improved guidance"}'

        call_idx = 0

        def mock_llm(*_args, **_kwargs):
            nonlocal call_idx
            call_idx += 1
            content = critic_response if call_idx == 1 else optimizer_response
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ContinuousEvolutionEngine(
                llm_client=mock_llm,
                checkpoints_dir=tmpdir,
            )

            results = [
                AgentRemediationResult(
                    status="SUCCESS",
                    rule_id="ISO-A.10-WEAK-HASH",
                    method_key="pkg.App#hash()",
                    target_method="pkg.App.hash()",
                    workspace_root="/tmp",
                    modified_files=["App.java"],
                    diff="+ SHA-256",
                    verification=AgentVerificationStatus(
                        compile_passed=True,
                        compile_output="",
                        tests_passed=True,
                        test_output="",
                        policy_passed=True,
                        policy_findings=[],
                        remaining_violations=[],
                    ),
                    turns=[AgentTurn(role="assistant", content="fixed", tool_calls=[AgentToolCall("1", "edit_file", {})])],
                    reason="Fixed",
                    iterations=1,
                ),
                AgentRemediationResult(
                    status="MAX_TURNS_EXCEEDED",
                    rule_id="ISO-A.8-SQL-INJECTION",
                    method_key="pkg.App#query()",
                    target_method="pkg.App.query()",
                    workspace_root="/tmp",
                    modified_files=[],
                    diff="",
                    verification=AgentVerificationStatus(
                        compile_passed=True,
                        compile_output="",
                        tests_passed=True,
                        test_output="",
                        policy_passed=False,
                        policy_findings=[],
                        remaining_violations=["ISO-A.8-SQL-INJECTION"],
                    ),
                    turns=[AgentTurn(role="assistant", content="test", tool_calls=[])],
                    reason="failed",
                    iterations=1,
                ),
            ]

            prompt, report = engine.evolve_epoch(1, "Initial system prompt", results)
            self.assertEqual(prompt, "Evolved system prompt v1")
            self.assertEqual(report.epoch, 1)
            self.assertEqual(report.pass_rate, 0.5)
            self.assertTrue((Path(tmpdir) / "SYSTEM_PROMPT_v1.md").exists())

