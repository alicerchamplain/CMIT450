| Rule | Weight | Where | Pattern | Exists for: |
|---|---|---|---|---|
| `userinfo_spoof` | +5 | text | `(?<![\w.@-])((?:[a-z0-9-]+\.)+TLD)@((?:[a-z0-9-]+\.)+TLD)(?![\w@-])` | Matching the Gamaredon userinfo spoof pattern like onmedservice[.]com[.]ua@opportunizz[.]pro |
| `ip_in_title` | +4 | title | `(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])` + `is_public_ip` | Matching Gamaredon-like pages that have IPs in the title |
| `storage_key_marker` | +4 | text | `/!\S+` | Matching Gamaredon-like pages that have the s3 storage key marker /! |
| `base64_in_title` | +2 | title | `(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{2,}={1,2}(?![A-Za-z0-9+/=])` + `decodes_to_printable` | Matching Gamaredon-like pages which have base64 encodded patterns in the title. |
| `api_sample_body` | +1 | description | `^Hello,\+world!$` | Matches posts that use the default API example body |
| `ip_literal` | +1 | text | `(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])` + `is_public_ip` | Matches pages that have IPs in the text |
| `email_address` | +1 | text | `(?<![\w.@-])[\w.+-]+@(?:[a-z0-9-]+\.)+TLD(?![\w@-])` + `_not_a_host_local_part` | Matches pages with email addresses |
| `telegram_link` | -1 | text | `(?:t\.me/\|telegram\.me/\|(?<![\w@])@[A-Za-z]\w{4,31}\b)` | Matches pages that has telegram links in them, reduces their score. |
| `templated_body` | -2 | computed | computed | Matches pages with spammed duplicate page bodies |
