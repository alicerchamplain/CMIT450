# Telegraph path rules: live probe, 25 October 2026

Before freezing the candidate title lists (issue #10) I needed to know how Telegraph turns a
page title into a path, because the crowd check and the sweep probe paths, not titles. The
API documentation gives only the format `Title-12-31` and says nothing about non-Latin titles,
case, spaces or the counter.

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

The same holds for the Cyrillic letter in a mixed-script path (finding 4). `іnstrukcіya-10-23`,
`ІNSTRUKCІYA-10-23` and `Іnstrukcіya-10-23` all return the page titled Інструкція with the same
`path` field, and likewise for `Іstorіya`, `Svіt` and `Vіdeo`. The Cyrillic letter is not folded
into Latin i, though: the all-Latin `Instrukciya-10-23` and `Istoriya-10-23` are different pages
(Russian titles Инструкция and История), `Video-10-17` is a third page titled "видео", and
`Svit-10-06` does not exist. The `path` field also preserves the creator's case: that last page
reports itself as `video-10-17`, lowercase.

### 3. The transliteration scheme, as far as the evidence goes

Letters confirmed from titles returned on Latin paths:

| Cyrillic | Path letters | Evidence (title → path) |
|---|---|---|
| й | j | Сергей → Sergej, Андрей → Andrej, Дмитрий → Dmitrij |
| ю | yu | Юлия → Yuliya |
| я | ya | Заявление → Zayavlenie |
| ж | zh | Жанна → Zhanna |
| щ | shch | Борщ → Borshch |
| ц | c | Цена → Cena, Пятница → Pyatnica, Інструкція → Іnstrukcіya |
| х | h | Хочу → Hochu, Хорошо → Horosho |
| ш | sh | Школа → Shkola, Саша → Sasha |
| ч | ch | Почта → Pochta, Чай → Chaj |
| ы | y | Выход → Vyhod |
| э | **eh** | Это → Ehto, Экономика → Ehkonomika, Эксперт → Ehkspert |
| ё | yo | Ёлка → Yolka, Алёна → Alyona |
| ь, ъ | dropped | Ольга → Olga, Компьютер → Kompyuter, Объявление → Obyavlenie |
| ф | f | Фото → Foto, Телефон → Telefon, Форма → Forma, two sightings each |
| е, и, а, о, у, в, л, н, р, с, т, з, к, п, м, д, б, г (ru) | e, i, a, o, u, v, l, n, r, s, t, z, k, p, m, d, b, g | the words above, plus Украина → Ukraina, Киев → Kiev |


### 4. Ukrainian letters: і is not transliterated at all

Telegraph's table is the Russian alphabet plus exactly three Ukrainian letters: ї, є and ґ.
Every other Cyrillic letter is passed through unchanged, so a Ukrainian title containing і
produces a mixed-script path, and so do Serbian and Macedonian titles. The clearest single piece
of evidence is a spam page whose title is mojibake, `Jk Й»‘Дёќ ЕђЋе…Ґ`, and whose path is
`Jk-JDyoќ-EђЋeG-10-27`: Й→J, Д→D, ё→yo, Е→E, е→e and Ґ→G are converted; ќ, ђ and Ћ (Macedonian
and Serbian) are kept; », ‘ and … are dropped; case is preserved letter by letter.

| Cyrillic | Path letters | Evidence (title → path) |
|---|---|---|
| и (uk) | i | Новини → Novini, three sightings on three days |
| ї | i | Київ → Kiiv, two sightings (10-07, 10-01) |
| є | ye | Євген → Yevgen, Європа → Yevropa, об'єкт → Obyekt |
| г (uk) | g, not h | Євген → Yevgen, Гра → neither `Hra` nor `Gra` carried a Ukrainian title |
| і | **Cyrillic і, kept as-is** | Відео → `Vіdeo`, Інструкція → `Іnstrukcіya`, Історія → `Іstorіya`, Світ → `Svіt` (four sightings; the API's own `path` field contains the Cyrillic letter) |
| ґ | g | Выбухны Ґ → `Vybuhny-G-08-12`, a Belarusian page about the letter, where the path token is the bare letter and the pass-through form `Vybuhny-Ґ-08-12` does not exist; `…Ґ` → `…G` in `Jk-JDyoќ-EђЋeG-10-27`; and Ґрати → `Grati` in `Rassekrechennoe-delo-…-Penthouse---Grati-11-17`. All three found by web search after 2,928 enumeration requests found nothing |
| ќ, ђ, Ћ (mk, sr) | **kept as-is** | `Jk-JDyoќ-EђЋeG-10-27` |

The alternatives for і were tested and got nothing in twenty days each: Latin `i` (`Video`,
`Privit`, `Film`, `Dim`, `Snig`, `Svit`, `Misto`, `Lito`, `Kit`), dropped (`Vdeo`, `Privt`,
`Flm`), and `y` (`Vydeo`, `Pryvyt`, `Fylm`, `Pryvit`). The hypothesis that ї is first decomposed
to і and then passed through (`Kiіv` with a Cyrillic і) also got nothing.

Consequence: a page titled Повістка lives at `Povіstka-MM-DD` with a Cyrillic і, sent on the
wire as `Pov%D1%96stka`. The Latin `Povistka` can never match it.

### 5. No "-1" page

On 24 October, `Hello-10-24` and `Hello-10-24-2` exist and `Hello-10-24-1` does not. The same
holds for `Test-10-24`. The first page of a day is bare and the second carries `-2`. The crowd
check's probe sequence is: bare, then 2, 3, 4 and so on.

### 6. Spaces become hyphens

`Hello-World-10-24` is titled "hello world". Requesting the path with a literal space (sent as
`%20`) returns `PAGE_NOT_FOUND`. Multi-word list entries must be hyphenated before the path is
built.

Hyphens already in the title are kept, and runs are not collapsed. The title "… до Penthouse -
Ґрати" gives `…-do-Penthouse---Grati`: space, hyphen, space become three hyphens. Punctuation
next to a space leaves nothing behind: "бикини». От" gives `bikini-Ot`, one hyphen from the one
space. slugify must therefore map each space to a hyphen, keep each hyphen, drop punctuation, and
never squeeze the result.

### 7. Not-found is HTTP 200

Every `PAGE_NOT_FOUND` response came with status 200. The envelope body, not the status code,
says whether a page exists.

### 8. Titles change after publication

`Hello-10-24-3` is now titled "TMP" and `Chat-10-24` is titled "DELETED". The path is fixed at
creation; the title in the response is whatever it is now. The letter probes turned up the same
thing from the other side: `Kyiv-10-08` is titled КИЇВ, `Kiiv-09-21` is titled "Як більшовики
нищили укра…" and `Vіdeo-10-17` is titled "Відео Вордпрес", none of which could have produced
those paths.

### 9. Apostrophes and punctuation are dropped

Здоров'я → `Zdorovya`, об'єкт → `Obyekt`, don't → `Dont`, it's → `Its`. The hyphenated
alternatives (`Don-t`, `It-s`, `Sim-ya`, `Ob-yavlenie`) never hit. Other punctuation goes the
same way: "Світ…" → `Svіt`, and in `Jk-JDyoќ-EђЋeG-10-27` the title's », ‘ and … all vanish
without leaving a hyphen.

## What this means for the word lists

1. **Keep the Cyrillic originals and generate the slugs.** The lists should hold titles as a
   person would type them. A `slugify` function, built from the tables in findings 3 and 4 and
   unit-tested against the sightings recorded here, turns each title into the path Telegraph
   would give it: Russian letters by the table, э as `eh`, Ukrainian і left as Cyrillic, ь/ъ and
   apostrophes dropped, spaces to hyphens. The hand-transliterated Latin lines that duplicate a
   Cyrillic original should be removed, because for any Ukrainian word containing і they are
   wrong, and for Russian words with э they are wrong too.
2. **The ru-names scheme is sound.** It uses `j` for й and `ya`/`yu` for я/ю, which is what
   Telegraph does. No change needed on that account.
3. **Case variants are unnecessary.** Finding 2 closes the question of whether to add lowercase
   entries.
4. **Hyphenate multi-word entries** (`Proxy List` → `Proxy-List`, `Hello World` → `Hello-World`)
   in the slugging step.
5. **Store the API's `path`, not the requested string**, so case differences cannot create
   duplicate rows.

## Open items

- Uppercase forms of letters that transliterate to two or more Latin letters (Ё, Ж, Ч, Ш, Щ, Э,
  Ю, Я, Є) have no sighting. Whether Ё gives `Yo` or `YO` is unknown; irrelevant to lookups,
  which are case-insensitive, but relevant to reproducing the API's `path` field exactly.
- Whether the daily counter is global per title or restarts: the crowd check will reveal it.
- Digits and other scripts in titles (Arabic, Persian, emoji) were not probed. The Test-10-16
  fixture is Persian content under a Latin title, so this matters for the benign tail.

## Appendix: paths probed

Batch 1 (33 requests), each for 10-24 and 10-23 unless noted: Privet/Привет, Test/Тест,
Novosti/Новости, Povistka/Повістка, Zayavlenie/Заявление, Yuliya/Юлия; then Hello-10-24,
Hello-10-24-1, Hello-10-24-2, Hello-10-24-3, Test-10-24-1, Test-10-24-2, Hello-World-10-24,
"Hello World-10-24", Reiestr-viiskovozobov'yazanykh-10-24.

Batch 2 (32 requests), all for 10-24: test, TEST, hello-world, privet; Sergej, Sergey, Sergei,
Andrej, Andrey, Andrei, Dmitrij, Dmitriy, Dmitry; Zhanna, Chat, Sasha, Borshch, Borsch, Cena,
Tsena, Hochu, Khochu, Eto, Elka, Yolka; Pryvit, Privit, Ukraina, Ukrayina, Novyny, Kyiv, Kiev.

Batch 3 (400 requests, stopped by the client's budget guard), dates 10-23 back to 10-14,
stopping a slug at its first Cyrillic-titled hit: Pryvit, Privit, Novyny, Novini, Noviny, Kyiv,
Kiiv, Kyyiv, Kiev; Ukraina, Ukrayina, Ukrajina, Yizha, Jizha, Izha; Evgen, Yevgen, Yevhen,
Jevgen, Evropa, Yevropa, Jevropa; Hroshi, Groshi, Hra, Gra; Hochu, Khochu, Horosho, Khorosho;
Shkola, Sasha; Pochta, Chaj, Chay, Chai; Vyhod, Vykhod, Vihod, Ryba, Riba; Eto, Ekran; Elka,
Yolka, Jolka, Alena, Alyona, Aljona; Olga, Ol-ga, Obyavlenie, Ob-yavlenie; Pyatnicya,
Pyatnitsya, P-yatnicya, Pyatnica, Kompyuter, Komp-yuter.

Batch 4 (303 requests), dates 10-23 back to 10-04, stopping only on a title containing the
target letter: Svit, Misto, Lito, Kit; Kiiv, Kyiv, Ukraina, Ukrayina; Era, Etazh, Elya; Simya,
Sim-ya, Imya, Zdorovya, Obyekt; Dont, Don-t, Its, It-s (five days only).

Batch 5 (178 requests): Video, Privit, Film, Snig, Dim; Eto, Ehto, Ekonomika, Ehkonomika,
Ekspert, Ehkspert, dates 10-23 back to 10-04; Kiiv and Novini for second sightings, dates 10-03
back to 09-14.

Batch 6 (167 requests), dates 10-23 back to 10-04: Vіdeo, Vdeo, Vydeo; Prіvіt, Privt, Pryvyt;
Fіlm, Flm, Fylm (і in the first of each triple is the Cyrillic letter).

Batch 7 (80 requests), same dates: Іnformaciya, Іnstrukcіya, Іstorіya, Svіt, Mіsto (Cyrillic і
and І), and Kiіv with a Cyrillic і in third position.

Batch 8 (155 requests), dates 10-23 back to 10-04: Foto, Telefon, Forma; Grunt, Ґrunt, Ganok,
Ґanok, Gudzik, Ґudzik; then the four known mixed-script pages each requested as found, with a
lowercase Cyrillic і, in all capitals, and with Latin i substituted.

Batches 9 and 10 (1,464 requests each, 8 per second), all 366 month-day slots: Gugl, Ґuґl,
Gadzhet, Ґadzhet; then adzhet, Hadzhet, Huhl, Hul.

Batch 11 (361 requests), dates 10-23 back to 10-04, table-breadth test: Sәlem, Salem, Saelem;
Қazaқsha, Kazaksha, Qazaqsha; Raқmet, Rakmet, Raqmet; Ўzbek, Uzbek, Ozbek; Srbiјa, Srbija; Ћao,
Cao, Chao; Belarus, Hlopchyk.

Batch 12 (4 requests): `Vybuhny-G-08-12`, found by web search.
