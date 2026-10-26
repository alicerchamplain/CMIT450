# Telegraph path rules: live probe, 25 October 2026

Before freezing the candidate title lists (issue #10) I needed to know how Telegraph turns a
page title into a path, because the crowd check and the sweep probe paths, not titles. The
API documentation gives only the format `Title-12-31` and says nothing about non-Latin titles,
case, spaces or the counter. This note records what two live probes
established, what they left open, and what changes to the word lists follow from it.

## Findings

### 1. Cyrillic titles get Latin paths

Every Cyrillic path probed returned `PAGE_NOT_FOUND`, twelve of twelve across two days. The
Latin form of the same word was found and its title came back in Cyrillic:

| Path requested | Outcome | Title returned |
|---|---|---|
| Privet-10-24 | FOUND | привет |
| Привет-10-24 | NOT_FOUND | |
| Zayavlenie-10-24 | FOUND | Заявление |
| Заявление-10-24 | NOT_FOUND | |
| Yuliya-10-24 | FOUND | Юлия |
| Юлия-10-24 | NOT_FOUND | |
| Novosti-10-24 | FOUND | новости |
| Новости-10-24 | NOT_FOUND | |

A Cyrillic string in a word list therefore probes a path that can never exist.

### 2. Path lookups are case-insensitive

`test-10-24`, `TEST-10-24` and `Test-10-24` all return the same page, titled Тест.
`hello-world-10-24` returns the page titled "hello world". `privet-10-24` returns the same page
as `Privet-10-24`. Lowercase variants of list entries are not needed, and two different request
strings can name one page, so the stored path must always be the `path` field the API returns,
not the string that was requested.

### 3. The transliteration scheme, as far as the evidence goes

Letters confirmed from titles returned on Latin paths:

| Cyrillic | Path letters | Evidence (title → path) |
|---|---|---|
| й | j | Сергей → Sergej, Андрей → Andrej, Дмитрий → Dmitrij |
| ю | yu | Юлия → Yuliya |
| я | ya | Заявление → Zayavlenie |
| ж | zh | Жанна → Zhanna |
| щ | shch | Борщ → Borshch |
| ц | c | Цена → Cena |
| е, и, а, о, у, в, л, н, р, с, т, з, к, п, м, д, г (ru) | e, i, a, o, u, v, l, n, r, s, t, z, k, p, m, d, g | the words above, plus Украина → Ukraina, Киев → Kiev |

Not yet observed: х, ш (alone), ч, ы, э, ё, ь, ъ.

### 4. Ukrainian letters are unverified

Nothing was found for `Pryvit`, `Privit`, `Novyny`, `Kyiv` or `Ukrayina`, and `Povistka`.
There is no evidence yet for how і, ї, є or Ukrainian г are transliterated.
I need to probe common Ukrainian words across many past dates
until it hits one.

### 5. No "-1" page

On 24 October, `Hello-10-24` and `Hello-10-24-2` exist and `Hello-10-24-1` does not. The same
holds for `Test-10-24`. The first page of a day is bare and the second carries `-2`. The crowd
check's probe sequence is: bare, then 2, 3, 4 and so on.

### 6. Spaces become hyphens

`Hello-World-10-24` is titled "hello world". Requesting the path with a literal space (sent as
`%20`) returns `PAGE_NOT_FOUND`. Multi-word list entries must be hyphenated before the path is
built.

### 7. Not-found is HTTP 200

Every `PAGE_NOT_FOUND` response came with status 200. The envelope body, not the status code,
says whether a page exists.

### 8. Titles change after publication

`Hello-10-24-3` is now titled "TMP" and `Chat-10-24` is titled "DELETED". The path is fixed at
creation; the title in the response is whatever it is now.

## What this means for the word lists

1. **I need to convert every Cyrillic entry.** Any words not already covered  should be transliterated using the
   scheme in finding 3 for Russian. Ukrainian words wait on finding 4.
2. **The ru-names scheme is sound.** It uses `j` for й and `ya`/`yu` for я/ю, which is what
   Telegraph does. No change needed on that account.
3. **Case variants are unnecessary.** Finding 2 closes the question of whether to add lowercase
   entries.
4. **Hyphenate multi-word entries** (`Proxy List` → `Proxy-List`, `Hello World` → `Hello-World`)
   in the slugging step.
5. **Store the API's `path`, not the requested string**, so case differences cannot create
   duplicate rows.

## Open items

- Ukrainian transliteration (і, ї, є, г): probe common words across past dates.
- Unobserved Russian letters (х, ш, ч, ы, э, ё): probe common words across past dates.
- Apostrophes in titles (`Реєстр військовозобов'язаних`): untested.
- Whether the daily counter is global per title or restarts: the crowd check will reveal it.

## Appendix: paths probed

Batch 1 (33 requests), each for 10-24 and 10-23 unless noted: Privet/Привет, Test/Тест,
Novosti/Новости, Povistka/Повістка, Zayavlenie/Заявление, Yuliya/Юлия; then Hello-10-24,
Hello-10-24-1, Hello-10-24-2, Hello-10-24-3, Test-10-24-1, Test-10-24-2, Hello-World-10-24,
"Hello World-10-24", Reiestr-viiskovozobov'yazanykh-10-24.

Batch 2 (32 requests), all for 10-24: test, TEST, hello-world, privet; Sergej, Sergey, Sergei,
Andrej, Andrey, Andrei, Dmitrij, Dmitriy, Dmitry; Zhanna, Chat, Sasha, Borshch, Borsch, Cena,
Tsena, Hochu, Khochu, Eto, Elka, Yolka; Pryvit, Privit, Ukraina, Ukrayina, Novyny, Kyiv, Kiev.
