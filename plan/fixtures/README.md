# Recorded api.telegra.ph/getPage responses (secrets redacted at capture)

- `Vizit-12-28.json`: known resolver, userinfo spoof in body
- `ki06-05-02.json`: known resolver, armed placeholder (hex token)
- `Hello-10-17-154.json`: Gamaredon daily page, pointer in title (storage keys redacted)
- `Hello-10-17-5.json`: benign page under the same title
- `Test-10-16.json`: benign control page
- `not-found.json`: the not-found response shape

## How they are made

The page fixtures are `graphwatch.redact.redact_page` applied to the raw API
responses.

To refresh them:

    python3 plan/fixtures/regenerate.py RAW_DIR

