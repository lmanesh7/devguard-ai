import requests, json, time
payload = {
    "repository": {
        "owner": {"login": "testowner"},
        "name": "testrepo"
    },
    "pull_request": {"number": 123, "title": "Test PR"}
}
url = "http://127.0.0.1:8000/webhook/github"
resp = requests.post(url, json=payload)
print('Status code:', resp.status_code)
print('Response body:', resp.text)
