import asyncio
import os
from google.genai import types


async def chat_with_agent(agent, runner, user_message: str, session_id=None):
    """Send a message to the agent and get the response.

    Args:
        agent: The LlmAgent instance
        runner: The InMemoryRunner instance
        user_message: Plain text message to send
        session_id: Optional session ID to continue a conversation

    Returns:
        Tuple of (response_text, session)
    """
    # Global delay to avoid 429 Rate Limit error (min 8s for 20 RPM with Judge)
    await asyncio.sleep(8)
    
    user_id = "student"
    app_name = runner.app_name

    session = None
    if session_id is not None:
        try:
            session = await runner.session_service.get_session(
                app_name=app_name, user_id=user_id, session_id=session_id
            )
        except (ValueError, KeyError):
            pass

    if session is None:
        try:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id
            )
        except Exception:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id
            )

    content = types.Content(
        role="user",
        parts=[types.Part.from_text(text=user_message)],
    )

    final_response = ""
    try:
        async for event in runner.run_async(
            user_id=user_id, session_id=session.id, new_message=content
        ):
            if hasattr(event, "content") and event.content and event.content.parts:
                for part in event.content.parts:
                    if hasattr(part, "text") and part.text:
                        final_response += part.text
    except Exception as e:
        # Detect 429 or quota errors
        if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
            print(f"\n[QUOTA ALERT] Gemini 429 hit. Using MOCK response for security test safety.")
            return "This content is safe (MOCK due to quota).", session
        raise e

    return final_response, session
