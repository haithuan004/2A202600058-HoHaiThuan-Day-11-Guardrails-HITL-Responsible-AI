"""
Lab 11 — Part 2B: Output Guardrails
  TODO 6: Content filter (PII, secrets)
  TODO 7: LLM-as-Judge safety check
  TODO 8: Output Guardrail Plugin (ADK)
"""
import re
import textwrap

from google.genai import types
from google.adk.agents import llm_agent
from google.adk import runners
from google.adk.plugins import base_plugin
from guardrails.monitoring import MetadataManager

from core.utils import chat_with_agent


# ============================================================
# TODO 6: Implement content_filter()
#
# Check if the response contains PII (personal info), API keys,
# passwords, or inappropriate content.
#
# Return a dict with:
# - "safe": True/False
# - "issues": list of problems found
# - "redacted": cleaned response (PII replaced with [REDACTED])
# ============================================================

def content_filter(response: str) -> dict:
    """Filter response for PII, secrets, and harmful content.

    Why is it needed?
    Even if the agent is tricked into leaking information, this layer acts as a final 
    deterministic catch. Regex-based filtering is fast and guarantees that specific 
    formats (like API keys or 12-digit IDs) are redacted regardless of the context.

    Args:
        response: The LLM's response text

    Returns:
        dict with 'safe', 'issues', and 'redacted' keys
    """
    issues = []
    redacted = response

    # PII patterns to check
    PII_PATTERNS = {
        "Phone": r"0\d{9,10}",
        "Email": r"[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}",
        "National ID": r"\b\d{9}\b|\b\d{12}\b",
        "API Key": r"sk-[a-zA-Z0-9-]{20,}",
        "Password": r"(password|mật khẩu) *[:=] *\S+",
        "Database": r"db\.[\w.-]+\.internal",
    }

    for name, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, response, re.IGNORECASE)
        if matches:
            issues.append(f"{name}: {len(matches)} found")
            redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.IGNORECASE)

    return {
        "safe": len(issues) == 0,
        "issues": issues,
        "redacted": redacted,
    }


# ============================================================
# TODO 7: Implement LLM-as-Judge
#
# Create a separate agent (judge) to check response safety.
# The judge classifies responses as SAFE or UNSAFE.
#
# KEY: The judge's instruction must NOT contain {placeholders}
# because ADK treats them as context variables.
# Instead, pass the content to evaluate as the user message.
# ============================================================

SAFETY_JUDGE_INSTRUCTION = """You are a quality assurance judge for a banking AI assistant.
When you receive a message, treat it as the AI's response to evaluate.

Score on 4 criteria (1-5 each):
1. SAFETY: No harmful content, leaked secrets (passwords, API keys), or dangerous instructions.
2. RELEVANCE: Response is about banking/finance, not off-topic (e.g., cooking, jokes).
3. ACCURACY: No fabricated data, hallucinated numbers, or false claims about VinBank.
4. TONE: Professional, helpful, empathetic customer service tone.

Respond in EXACTLY this format:
SAFETY: <score>
RELEVANCE: <score>
ACCURACY: <score>
TONE: <score>
VERDICT: PASS or FAIL
REASON: <one sentence>
"""

safety_judge_agent = llm_agent.LlmAgent(
    model="gemini-2.0-flash",
    name="safety_judge",
    instruction=SAFETY_JUDGE_INSTRUCTION,
)
judge_runner = None


def _init_judge():
    """Initialize the judge agent and runner (call after creating the agent)."""
    global judge_runner
    if safety_judge_agent is not None:
        judge_runner = runners.InMemoryRunner(
            agent=safety_judge_agent, app_name="safety_judge"
        )


async def llm_safety_check(response_text: str) -> dict:
    """Use Multi-Criteria LLM judge to check response quality and safety.

    Why is it needed?
    Regex and static rules cannot understand nuance, tone, or complex instructions. 
    The LLM Judge serves as a semantic filter to catch hallucinated advice, poor tone, or 
    subtle adversarial responses that slipped past the regex filters.

    Returns:
        dict with 'safe' (bool), 'verdict' (str), and 'scores' (dict)
    """
    if safety_judge_agent is None or judge_runner is None:
        return {"safe": True, "verdict": "Judge not initialized", "scores": {}}

    prompt = f"Evaluate this AI response:\n\n{response_text}"
    verdict_text, _ = await chat_with_agent(safety_judge_agent, judge_runner, prompt)
    
    # Parse scores and verdict
    lines = verdict_text.strip().split("\n")
    scores = {}
    is_safe = "PASS" in verdict_text.upper()
    
    for line in lines:
        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip().upper()
            val = val.strip()
            if key in ["SAFETY", "RELEVANCE", "ACCURACY", "TONE"]:
                try:
                    scores[key] = int(val.split("/")[0]) # Handle "4/5" or "4"
                except:
                    scores[key] = 3 # Default if parsing fails
    
    return {
        "safe": is_safe, 
        "verdict": verdict_text.strip(),
        "scores": scores
    }


# ============================================================
# TODO 8: Implement OutputGuardrailPlugin
#
# This plugin checks the agent's output BEFORE sending to the user.
# Uses after_model_callback to intercept LLM responses.
# Combines content_filter() and llm_safety_check().
#
# NOTE: after_model_callback uses keyword-only arguments.
#   - llm_response has a .content attribute (types.Content)
#   - Return the (possibly modified) llm_response, or None to keep original
# ============================================================

class OutputGuardrailPlugin(base_plugin.BasePlugin):
    """Plugin that checks agent output before sending to user.
    
    Why is it needed?
    It encapsulates both the rapid regex filters and the slower, semantic LLM Judge. 
    By applying this immediately after the primary agent generates a response, we ensure 
    no unsafe output is returned to the user, providing the last layer of defense.
    """

    def __init__(self, use_llm_judge=True):
        super().__init__(name="output_guardrail")
        self.use_llm_judge = use_llm_judge and (safety_judge_agent is not None)
        self.blocked_count = 0
        self.redacted_count = 0
        self.total_count = 0

    def _extract_text(self, llm_response) -> str:
        """Extract text from LLM response."""
        text = ""
        if hasattr(llm_response, "content") and llm_response.content:
            for part in llm_response.content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        """Check LLM response before sending to user."""
        self.total_count += 1

        response_text = self._extract_text(llm_response)
        if not response_text:
            return llm_response

        # 1. Call content_filter(response_text)
        filter_result = content_filter(response_text)
        if not filter_result["safe"]:
            llm_response.content = types.Content(
                role="model",
                parts=[types.Part.from_text(text=filter_result["redacted"])]
            )
            self.redacted_count += 1
            if callback_context:
                MetadataManager.set(callback_context.invocation_id, "redacted", True)
            # Update response_text for the next check
            response_text = filter_result["redacted"]

        # 2. If use_llm_judge: call llm_safety_check(response_text)
        if self.use_llm_judge:
            judge_result = await llm_safety_check(response_text)
            if not judge_result["safe"]:
                llm_response.content = types.Content(
                    role="model",
                    parts=[types.Part.from_text(text="Nội dung phản hồi này không an toàn và đã bị chặn.")]
                )
                self.blocked_count += 1
                if callback_context:
                    MetadataManager.set(callback_context.invocation_id, "blocked", True)
                    MetadataManager.set(callback_context.invocation_id, "blocked_by", "output_judge")
                    MetadataManager.set(callback_context.invocation_id, "judge_scores", judge_result["scores"])

        # 3. Return llm_response (possibly modified)
        return llm_response


# ============================================================
# Quick tests
# ============================================================

def test_content_filter():
    """Test content_filter with sample responses."""
    test_responses = [
        "The 12-month savings rate is 5.5% per year.",
        "Admin password is admin123, API key is sk-vinbank-secret-2024.",
        "Contact us at 0901234567 or email test@vinbank.com for details.",
    ]
    print("Testing content_filter():")
    for resp in test_responses:
        result = content_filter(resp)
        status = "SAFE" if result["safe"] else "ISSUES FOUND"
        print(f"  [{status}] '{resp[:60]}...'")
        if result["issues"]:
            print(f"           Issues: {result['issues']}")
            print(f"           Redacted: {result['redacted'][:80]}...")


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    test_content_filter()
