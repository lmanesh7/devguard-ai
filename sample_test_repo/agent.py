"""Demo Agent module using Akamai Hosted AI."""

SYSTEM_PROMPT = "You are a secure, helpful cloud assistant."


def generate_response(user_input: str) -> list[dict]:
    # Proper, isolated message formatting
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_input},
    ]
