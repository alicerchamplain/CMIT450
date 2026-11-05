# Issue #22 - Shape notes - 2026-11-05

I've analyzed a few hundred stored pages manually and then did some SQL searches across the database to learn what the data looks like before any
rule is written for Issue #23.

## Sample

| Stratum | Pages | Sampled |
|---|---|---|
| Source list, 9 lists | 657 (lures) to 45,149 (ru-names) | 30 each |
| 30-day volume band of the title: 1 to 9 pages | 280 | 30 |
| 10 to 99 | 3,239 | 30 |
| 100 to 999 | 36,828 | 30 |
| 1,000 to 9,999 | 52,630 | 30 |
| **Pages read** | | **389** |


## What the database looks like

| Stratum | Pages | Median body chars | Has URL | Has t.me link | Has @handle | Has IP literal | Duplicate of another page | Zero views |
|---|---|---|---|---|---|---|---|---|
| band 1 to 9 | 280 | 911 | 24% | 8% | 9% | 3% | 2% | 2% |
| band 10 to 99 | 3,239 | 839 | 23% | 12% | 7% | 1% | 21% | 6% |
| band 100 to 999 | 36,828 | 234 | 66% | 56% | 6% | 0% | 62% | 7% |
| band 1k to 9k | 52,630 | 442 | 28% | 21% | 54% | 0% | 36% | 20% |
| brand-phishing | 12,068 | 118 | 36% | 22% | 55% | 0% | 36% | 3% |
| c2-tooling | 3,233 | 234 | 89% | 72% | 8% | 0% | 81% | 11% |
| crypto-theft | 3,036 | 234 | 78% | 72% | 4% | 0% | 70% | 3% |
| greetings | 20,624 | 234 | 46% | 18% | 21% | 1% | 53% | 8% |
| lures | 657 | 234 | 54% | 30% | 24% | 0% | 49% | 5% |
| proxy | 1,745 | 161 | 63% | 51% | 2% | 1% | 54% | 13% |
| ru-names | 45,149 | 442 | 35% | 39% | 42% | 0% | 40% | 23% |
| stealer-markets | 3,963 | 85 | 33% | 30% | 1% | 0% | 31% | 2% |
| trackers-droppers | 2,502 | 234 | 84% | 64% | 5% | 0% | 66% | 9% |
| **all** | **92,977** | **234** | **43%** | **35%** | **33%** | **0.2%** | **46%** | **14%** |

Three findings:

1. **Half the pages are copies.** 46% of pages share their exact fingerprint
   with at least one other page.
2. **The threat wordlists are the most duplicated.** c2-tooling,
   crypto-theft, trackers-droppers and proxy are 54% to 81% duplicates and
   64% to 72% t.me links.
3. **IP addresses are rare.** 221 pages in 92,977 carry one. That is the
   single most selective feature in the database.

## The shapes

| Shape | Pages | Share | Median views | Where it lives |
|---|---|---|---|---|
| **Known DDR actor** | **55** | **0.06%** | 1 | Hello only |
| Title squatter A: `SLlV_INTIM_BOT` keyword page | 12,785 | 13.8% | 11 | 418 of 788 titles |
| Title squatter B: `+YztOEovieQIzZjY8` "exploits, RATs" ad | 9,032 | 9.7% | 3 | 427 of 788 titles |
| "Sliv" doxx and VIP-bot ads under women's names | 16,652 | 17.9% | 1 | ru-names |
| Hindi/Telugu movie link spam (mdisk, terabox, "PAGE 1") | 7,649 | 8.2% | 18 | greetings, any English word |
| Telegram Premium / SpyBot phish | 6,144 | 6.6% | 14 | Telegram |
| Placeholder, test or empty body | 10,408 | 11.2% | 22 | everywhere |
| Long prose without links: stories, erotica, essays, roleplay forms | 7,451 | 8.0% | 26 | ru-names |
| RSS and news reposts | 3,506 | 3.8% | 11 | Novosti, News |
| Shop and price-list posts | 1,380 | 1.5% | 62 | amazon, Kuhnya, Stul |
| Drive/mirror bot help text | 364 | 0.4% | 37 | HELP, Help |
| Leaked data  | 298 | 0.3% | 18 | data, privet, title, proxy words |
| Dating-site autologin links | 122 | 0.1% | 34 | Confirm |
| Casino, betting, pharma SEO | 86 | 0.1% | 7 | brand words |
| Everything else: short notes, single links, more templates | 17,045 | 18.3% | 14 | |



### Title squatters

Two spammers post the same page under hundreds of different titles every
day.

| | Squatter A | Squatter B |
|---|---|---|
| Body | one t.me link to a bot, then a keyword list in Russian and English | the same t.me invite link three times, "exploits, malware, RATs, steallers and other stuff" |
| Pages in frame | 12,785 | 9,032 |
| Distinct titles | 418 of 788 | 427 of 788 |
| Days active in frame | 7 of 14, in bursts from 20 October (4,541 pages on 31 October) | 13 of 14 |
| Pages per day, median | 1,427 | 1,007 |
| Title equals the slug | 99.4% | 98.9% |
| Posted at counter 1 to 5 | 57% | 61% |
| Share of c2-tooling pages | 43% | 29% |
| Share of trackers-droppers pages | 37% | 26% |
| Share of crypto-theft pages | 39% | 29% |


### The known threat actor(s?)

55 Hello pages in two shapes:

| Shape | Pages | Title | Description and body |
|---|---|---|---|
| Pointer | 27 | `207.246.108.214?<spoof host>@opportunizz.pro/!<key>?<key>?<b64>?<b64>` | `Hello,+world!` |
| Spoof URL | 28 | `<spoof host>@<front>`, fronts on `workers.dev` (15) and `trycloudflare.com` (13) | `Hello,+world!` |

The fetch on 2026-11-04 caught all of the Pointer shaped pages
rotating to `45.77.93[.]187`.


`Hello,+world!` is the body from Telegraph's `createPage` API
example, which means the threat actor likely posts using the API with the sample content
unchanged. The Hello,+world! string is a marker of API use, not unique to the actor.

### Leaked data

Found in passing, all secrets were already hashed at ingest.

| Kind | Pages | Shape |
|---|---|---|
| Telegram session export, JSON beginning `WARNING_BANNER` | 99 | 36 KB of JSON under `data`, `privet`, `title`, `Kod` |
| Telegram app `api_id` and `api_hash` | 4 | `Bot`, `api` |
| Proxy lists, `ss://`, `vless` JSON configs | 93 | `proxy`, `ss`, `Free-proxies`, `vless` |
| `email:password` combos | 17 | `Netflix`, `Akkaunt` |
| Dating-site tracking and autologin URLs | 286 | `Confirm` |
| Card and payment pages | 3 | `cvv`, `cc` |
| Doxx posts: full name, phone, address, passport-style fields | 36 | ru-names, `privet` |


## What separates the dead drop resolvers


| Feature | Actor pages | Non-actor pages | Verdict |
|---|---|---|---|
| `host@host` userinfo spoof in the title | 55 | 0 | exact |
| IP literal in the title | 27 | 0 | exact |
| `/!` storage-key marker anywhere | 27 | 0 | exact |
| Base64 padding (`=`, `==`) in the title | 27 | 1 (a pasted `<script>` block) | exact in practice |
| `host@host` anywhere, strict host on both sides | 55 | 1 (an email in a description) | exact; loose email patterns match 218 |



## What this means for Issue #23

1. The rule table should start with the five features above.
2. I need to add a way to flag and supress templated/duplicate posts to avoid scoring or categorizing the same page multiple times.
3. The rule table should include IP address shapes as those are relatively rare.
