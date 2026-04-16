"""
Assignment 11 — Part 5 & 6: Monitoring, Auditing & Rate Limiting
"""
import json
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

from typing import Any
from google.genai import types
from google.adk.plugins import base_plugin


class MetadataManager:
    """Singleton to share metadata across plugins during an invocation.
    
    What does this component do?
    Provides a centralized, in-memory key-value store tied to specific invocation IDs, 
    allowing different plugins in the pipeline to pass state to each other.

    Why is it needed?
    Because the Google ADK plugins operate sequentially and the `InvocationContext` is 
    often read-only, we need a side-channel to record flags (like `blocked=True` from 
    `InputGuardrail`) so that the `AuditLogPlugin` at the end of the chain knows *why* 
    an interaction failed and can log it properly.
    """
    _store = defaultdict(dict)

    @classmethod
    def set(cls, invocation_id: str, key: str, value: Any):
        cls._store[invocation_id][key] = value

    @classmethod
    def get_all(cls, invocation_id: str) -> dict:
        return cls._store.get(invocation_id, {})

    @classmethod
    def clear(cls, invocation_id: str):
        cls._store.pop(invocation_id, None)


class RateLimitPlugin(base_plugin.BasePlugin):
    """Plugin to block users who send too many requests in a time window.
    
    Why is it needed?
    It catches Denial of Service (DoS) attacks, brute-force injection attempts, or 
    automated scraping. Other layers (like InputGuardrail) only analyze the text of a 
    *single* request and cannot detect high-frequency abuse across multiple requests.
    """

    # Window increased to 5 mins (300s) to show blocking even with 8s throttle
    def __init__(self, max_requests=10, window_seconds=300):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows = defaultdict(deque)
        self.blocked_count = 0

    def _block_response(self, wait_time: int) -> types.Content:
        """Create a block message with wait time."""
        return types.Content(
            role="model",
            parts=[types.Part.from_text(
                text=f"Too many requests. Please wait {wait_time} seconds before trying again."
            )],
        )

    async def on_user_message_callback(
        self,
        *,
        invocation_context,
        user_message: types.Content,
    ) -> types.Content | None:
        user_id = invocation_context.user_id if invocation_context else "student"
        now = time.time()
        window = self.user_windows[user_id]

        # Remove expired timestamps
        while window and window[0] < now - self.window_seconds:
            window.popleft()

        # Check limit
        if len(window) >= self.max_requests:
            wait_time = int(self.window_seconds - (now - window[0]))
            self.blocked_count += 1
            if invocation_context:
                MetadataManager.set(invocation_context.invocation_id, "blocked", True)
                MetadataManager.set(invocation_context.invocation_id, "blocked_by", "rate_limit")
            return self._block_response(wait_time)

        # Allow and record timestamp
        window.append(now)
        return None


class AuditLogPlugin(base_plugin.BasePlugin):
    """Plugin to record interaction metadata and export to JSON.
    
    Why is it needed?
    While it doesn't block attacks directly, it provides visibility. It is needed for 
    post-incident forensics to understand *how* an attacker bypassed the system and to 
    identify zero-day vulnerabilities that the current guardrails missed.
    """

    def __init__(self, log_file="audit_log.json"):
        super().__init__(name="audit_log")
        self.log_file = log_file
        self.logs = []
        # Store metadata keyed by invocation_id since we can't modify InvocationContext directly
        self.metadata_store = defaultdict(dict)

    def _extract_text(self, content: types.Content) -> str:
        if not content or not content.parts:
            return ""
        return "".join(p.text for p in content.parts if hasattr(p, "text") and p.text)

    def set_metadata(self, invocation_id: str, key: str, value: Any):
        """Helper to set metadata for an invocation."""
        self.metadata_store[invocation_id][key] = value

    async def on_user_message_callback(
        self,
        *,
        invocation_context,
        user_message: types.Content,
    ) -> None:
        inv_id = invocation_context.invocation_id
        MetadataManager.set(inv_id, "start_time", time.time())
        MetadataManager.set(inv_id, "input_text", self._extract_text(user_message))
        return None

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        inv_id = callback_context.invocation_id
        metadata = MetadataManager.get_all(inv_id)
        
        end_time = time.time()
        start_time = metadata.get("start_time", end_time)
        input_text = metadata.get("input_text", "")
        output_text = self._extract_text(llm_response.content) if hasattr(llm_response, "content") else ""

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "invocation_id": inv_id,
            "user_id": callback_context.user_id if callback_context else "student",
            "input": input_text,
            "output": output_text,
            "latency_ms": int((end_time - start_time) * 1000),
            "blocked": metadata.get("blocked", False),
            "blocked_by": metadata.get("blocked_by", None),
            "redacted": metadata.get("redacted", False),
            "judge_scores": metadata.get("judge_scores", None),
        }
        self.logs.append(log_entry)
        self.export_json()
        
        # Cleanup store
        MetadataManager.clear(inv_id)
        
        return llm_response

    def export_json(self):
        """Export logs to JSON file."""
        try:
            with open(self.log_file, "w", encoding="utf-8") as f:
                json.dump(self.logs, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving audit logs: {e}")


class CostGuardPlugin(base_plugin.BasePlugin):
    """Plugin tracking character count/usage to prevent budget exhaustion.
    
    Why is it needed?
    Even if an attack is technically safe (no PII, no prompt injection), a user might 
    send massive text blocks intentionally to exhaust our LLM token budget (Economic 
    Denial of Sustainability - EDOS). This layer catches abnormally large payloads that 
    other layers might approve.
    """

    def __init__(self, max_chars_per_request=2000):
        super().__init__(name="cost_guard")
        self.max_chars_per_request = max_chars_per_request
        self.blocked_count = 0
        self.total_count = 0

    async def on_user_message_callback(
        self,
        *,
        invocation_context,
        user_message: types.Content,
    ) -> types.Content | None:
        self.total_count += 1
        text = ""
        if user_message and user_message.parts:
            text = "".join(p.text for p in user_message.parts if hasattr(p, "text") and p.text)
        
        if len(text) > self.max_chars_per_request:
            self.blocked_count += 1
            if invocation_context:
                MetadataManager.set(invocation_context.invocation_id, "blocked", True)
                MetadataManager.set(invocation_context.invocation_id, "blocked_by", "cost_guard")
            return types.Content(
                role="model",
                parts=[types.Part.from_text(text="Request too long. Please reduce text size to save API costs.")]
            )
        
        return None

class MonitoringAlert:
    """Watch plugin metrics and fire alerts on anomalies.
    
    What does this component do?
    Aggregates counters (`total_count`, `blocked_count`) from all registered plugins 
    and checks if the blockage rate exceeds a defined threshold (e.g., 30%). If it does, 
    it fires a console alert.

    Why is it needed?
    While the `AuditLogPlugin` writes static logs, `MonitoringAlert` provides real-time 
    observability. If an attacker mounts a massive automated attack, this component will 
    alert the operations team immediately, enabling active incident response rather than 
    passive forensic analysis.
    """

    def __init__(self, plugins, block_threshold=0.3):
        self.plugins = {p.name: p for p in plugins if hasattr(p, "name")}
        self.block_threshold = block_threshold

    def check_metrics(self):
        """Analyze current stats and print alerts."""
        print("\n" + "-" * 40)
        print("MONITORING SYSTEM CHECK")
        print("-" * 40)
        
        total_requests = 0
        total_blocked = 0
        
        for name, plugin in self.plugins.items():
            if hasattr(plugin, "blocked_count") and hasattr(plugin, "total_count"):
                total_requests = max(total_requests, plugin.total_count)
                total_blocked += plugin.blocked_count
                
                block_rate = plugin.blocked_count / plugin.total_count if plugin.total_count > 0 else 0
                if block_rate > self.block_threshold:
                    print(f"ALERT: High block rate on [{name}]: {block_rate:.0%}")
            
            # Special check for Rate Limit
            if name == "rate_limiter" and plugin.blocked_count > 0:
                 print(f"NOTICE: Rate limiter engaged {plugin.blocked_count} times.")

        print(f"Total Block Rate: {total_blocked}/{total_requests} requests")
        print("-" * 40)
