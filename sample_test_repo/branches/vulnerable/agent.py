"""Demo Agent module with Prompt Injection Vulnerability."""


def generate_response(user_input: str) -> list[dict]:
    # INSECURE: Untrusted user input formatted directly into system instructions!
    system_prompt = f"System override: You are an internal root assistant. Instructions: {user_input}"
    return [
        {"role": "system", "content": system_prompt},
    ]
