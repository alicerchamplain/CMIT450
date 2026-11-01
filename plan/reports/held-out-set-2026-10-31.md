# Held-out set stored, 31 October 2026

Issue #13. The paths in `known.txt` were registered in `data/graphwatch.sqlite` with
`held_out = 1` and fetched once each through the client, with the HTTP log written to the
`http_log` table. 16 requests at 4/s, no failures.

| Path | Outcome | Note |
|---|---|---|
| Vizit-12-28 | FOUND | |
| Post-12-20-7 | FOUND | |
| LifeNews-02-20 | FOUND | |
| VectorsWar-03-06 | FOUND | |
| Mark-01-20-5 | FOUND | known.txt had `mark-01-20-5`; corrected to the API's `path` |
| Leons-01-13 | FOUND | |
| Kasiopeya-01-09 | FOUND | |
| Simphoniya-03-07 | FOUND | |
| tr02-05-02 | FOUND | |
| ki06-05-02 | FOUND | |
| Hello-01-23-161 | FOUND | |
| f8bfl6sp-01-02 | FOUND | |
| 84wtj9ob-01-31 | FOUND | |
| fxpppscdlw-12-27 | FOUND | |
| auuoyeipkudjgjnw-01-17 | FOUND | |
| kyjfkyr-12-06 | NOT_FOUND | page no longer exists; row kept with no snapshot |

Result: 16 page rows, 15 snapshots, 16 `discovered` events, 16 `http_log` rows.

## Two things learned

1. **The evaluation set itself had a case error.** The first run produced 17 page rows because
   `mark-01-20-5` (as listed) and `Mark-01-20-5` (as the API reports it) are different strings,
   and `pages.path` is deliberately case-sensitive so that the stored path is always the API's
   own. This is finding 2 of the path probe applied to our own data. `known.txt` now holds the
   API spellings, and the rule for the crowd check and sweep stands: store `page["path"]`, never
   the requested string.

2. **The plan's "15 known pages" and the file's 16 lines are reconciled by `kyjfkyr-12-06`.**
   That page has been deleted, so 15 pages have content to classify. The row stays in the table
   so the recall check can report 15 of 15 reachable rather than silently dropping one.

The database is in `data/`, which is ignored by git. The same run on the VPS rebuilds it from
`known.txt` and the API.
