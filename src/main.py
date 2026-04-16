"""
Lab 11 — Main Entry Point
Run the full lab flow: attack -> defend -> test -> HITL design

Usage:
    python main.py              # Run all parts
    python main.py --part 1     # Run only Part 1 (attacks)
    python main.py --part 2     # Run only Part 2 (guardrails)
    python main.py --part 3     # Run only Part 3 (testing pipeline)
    python main.py --part 4     # Run only Part 4 (HITL design)
"""
import sys
import asyncio
import argparse

from core.config import setup_api_key
from guardrails.input_guardrails import InputGuardrailPlugin
from guardrails.output_guardrails import OutputGuardrailPlugin, _init_judge
from guardrails.monitoring import RateLimitPlugin, AuditLogPlugin, MonitoringAlert, CostGuardPlugin


async def part1_attacks():
    """Part 1: Attack an unprotected agent."""
    print("\n" + "=" * 60)
    print("PART 1: Attack Unprotected Agent")
    print("=" * 60)

    from agents.agent import create_unsafe_agent, test_agent
    from attacks.attacks import run_attacks, generate_ai_attacks

    # Create and test the unsafe agent
    agent, runner = create_unsafe_agent()
    await test_agent(agent, runner)

    # TODO 1: Run manual adversarial prompts
    print("\n--- Running manual attacks (TODO 1) ---")
    results = await run_attacks(agent, runner)

    # TODO 2: Generate AI attack test cases
    print("\n--- Generating AI attacks (TODO 2) ---")
    ai_attacks = await generate_ai_attacks()
    ai_results = await run_attacks(agent, runner, prompts=ai_attacks)

    return results + ai_results


async def part2_guardrails():
    """Part 2: Implement and test guardrails."""
    print("\n" + "=" * 60)
    print("PART 2: Guardrails")
    print("=" * 60)

    # Part 2A: Input guardrails
    print("\n--- Part 2A: Input Guardrails ---")
    from guardrails.input_guardrails import (
        test_injection_detection,
        test_topic_filter,
        test_input_plugin,
    )
    test_injection_detection()
    print()
    test_topic_filter()
    print()
    await test_input_plugin()

    # Part 2B: Output guardrails
    print("\n--- Part 2B: Output Guardrails ---")
    from guardrails.output_guardrails import test_content_filter, _init_judge
    _init_judge()  # Initialize LLM judge if TODO 7 is done
    test_content_filter()

    # Part 2C: NeMo Guardrails
    print("\n--- Part 2C: NeMo Guardrails ---")
    try:
        from guardrails.nemo_guardrails import init_nemo, test_nemo_guardrails
        init_nemo()
        await test_nemo_guardrails()
    except ImportError:
        print("NeMo Guardrails not available. Skipping Part 2C.")
    except Exception as e:
        print(f"NeMo error: {e}. Skipping Part 2C.")


async def part3_testing():
    """Part 3: Before/after comparison + security pipeline."""
    print("\n" + "=" * 60)
    print("PART 3: Security Testing Pipeline")
    print("=" * 60)

    from testing.testing import run_comparison, print_comparison, SecurityTestPipeline
    from agents.agent import create_unsafe_agent

    # TODO 10: Before vs after comparison
    print("\n--- TODO 10: Before/After Comparison ---")
    unprotected, protected = await run_comparison()
    if unprotected and protected:
        print_comparison(unprotected, protected)
    else:
        print("Complete TODO 10 to see the comparison.")

    # TODO 11: Automated security pipeline
    print("\n--- TODO 11: Security Test Pipeline ---")
    agent, runner = create_unsafe_agent()
    pipeline = SecurityTestPipeline(agent, runner)
    results = await pipeline.run_all()
    if results:
        pipeline.print_report(results)
    else:
        print("Complete TODO 11 to see the pipeline report.")


def part4_hitl():
    """Part 4: HITL design."""
    print("\n" + "=" * 60)
    print("PART 4: Human-in-the-Loop Design")
    print("=" * 60)

    from hitl.hitl import test_confidence_router, test_hitl_points

    # TODO 12: Confidence Router
    print("\n--- TODO 12: Confidence Router ---")
    test_confidence_router()

    # TODO 13: HITL Decision Points
    print("\n--- TODO 13: HITL Decision Points ---")
    test_hitl_points()


async def part5_production_pipeline():
    """Part 5: Full Assignment 11 Production Defense-in-Depth Pipeline."""
    print("\n" + "=" * 60)
    print("PART 5: Assignment 11 Production Defense Pipeline")
    print("=" * 60)

    from agents.agent import create_protected_agent
    from testing.testing import SecurityTestPipeline

    # 1. Initialize all safety layers
    # Defense-in-Depth chain:
    # RateLimit -> InputGuard -> NeMo -> OutputGuard (PII + Judge) -> AuditLog
    audit_log = AuditLogPlugin(log_file="audit_log.json")
    production_plugins = [
        RateLimitPlugin(max_requests=10, window_seconds=60), # Part 1
        InputGuardrailPlugin(),                             # Part 2
        CostGuardPlugin(max_chars_per_request=300),         # Bonus 6th Layer
        OutputGuardrailPlugin(use_llm_judge=True),          # Part 3 & 4
        audit_log,                                          # Part 5
    ]
    
    # 2. Add NeMo if available
    try:
        from guardrails.nemo_guardrails import NemoGuardPlugin, COLANG, YAML
        production_plugins.insert(2, NemoGuardPlugin(colang_content=COLANG, yaml_content=YAML))
        print("NeMo Guardrails integrated into pipeline.")
    except Exception as e:
        print(f"NeMo Guardrails skipped or error: {e}")

    # 3. Create the end-to-end protected agent (Start with Judge OFF for baseline)
    _init_judge()
    agent, runner = create_protected_agent(plugins=production_plugins)
    
    # Toggle judge for specific tests
    def toggle_judge(enabled: bool):
        for p in production_plugins:
            if p.name == "output_guardrail":
                p.use_llm_judge = enabled

    # 4. Run the Assignment 11 Test Suites
    pipeline = SecurityTestPipeline(agent, runner)
    
    # Test 1: Safe Queries (Regex + PII is enough)
    print("\n--- Running Test 1: Safe Queries ---")
    toggle_judge(False)
    safe_results = await pipeline.run_all(pipeline.SAFE_QUERIES)
    print("Wait 30s to reset quota...")
    await asyncio.sleep(30)
    
    # Test 2: Attack Queries (Regex + NeMo + PII is enough)
    print("\n--- Running Test 2: Attack Queries ---")
    toggle_judge(False)
    attack_results = await pipeline.run_all(pipeline.ATTACK_QUERIES)
    print("Wait 30s to reset quota...")
    await asyncio.sleep(30)
    
    # Test 3: Rate Limiting
    print("\n--- Running Test 3: Rate Limiting ---")
    print("Wait 70s to fully reset Gemini 20 RPM quota...")
    await asyncio.sleep(70) 
    toggle_judge(False)
    await pipeline.run_rate_limit_test()
    print("Wait 30s to reset quota...")
    await asyncio.sleep(30)

    # Test 4: Edge Cases (USE JUDGE for quality check)
    print("\n--- Running Test 4: Edge Cases ---")
    toggle_judge(True)
    edge_results = await pipeline.run_all(pipeline.EDGE_CASES)
    
    # 5. Monitoring & Alerts (Part 6)
    monitor = MonitoringAlert(plugins=production_plugins)
    monitor.check_metrics()
    
    # 6. Final Audit Log Export
    print(f"\nAudit logs saved to: {audit_log.log_file}")
    
    print("\nPipeline execution complete. Review the results above.")

async def main(parts=None):
    """Run the full lab or specific parts.

    Args:
        parts: List of part numbers to run, or None for all
    """
    setup_api_key()

    if parts is None:
        parts = [1, 2, 3, 4, 5]

    for part in parts:
        if part == 1:
            await part1_attacks()
        elif part == 2:
            await part2_guardrails()
        elif part == 3:
            await part3_testing()
        elif part == 4:
            part4_hitl()
        elif part == 5:
            await part5_production_pipeline()
        else:
            print(f"Unknown part: {part}")

    print("\n" + "=" * 60)
    print("Lab 11 complete! Check your results above.")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Lab 11: Guardrails, HITL & Responsible AI"
    )
    parser.add_argument(
        "--part", type=int, choices=[1, 2, 3, 4, 5],
        help="Run only a specific part (1-5). Default: run all.",
    )
    args = parser.parse_args()

    if args.part:
        asyncio.run(main(parts=[args.part]))
    else:
        asyncio.run(main())
