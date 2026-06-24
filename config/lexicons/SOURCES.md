# Lexicon sources & licensing

Compact word lists backing the `person_name` dictionary detector. All public-domain
or freely redistributable. Kept small for the endpoint budget; production can expand.

| File | Lines | Source | Licence |
|---|---|---|---|
| `surnames.txt` | 10,000 | US Census Bureau, 2010 Decennial surname file (top 10k by frequency, `Names_2010Census.csv`) | Public domain (US Gov work) |
| `given_names.txt` | 4,921 | `dominictarr/random-name` first-names list, normalised | Public list |
| `common_words.txt` | 300 | `first20hours/google-10000-english` (USA, top 300) | Public domain / MIT-style |

Normalisation: lowercased, alphabetic only, length ≥ 2, de-duplicated.

## Why three lists
- **surnames + given_names** = recall (what *looks* like a name).
- **common_words** = precision. It is a **tight top-300 high-frequency** list, not a
  big dictionary. A token in it is *excluded* from counting as name evidence even if
  it is in a name list — so `Will`/`May`/`Contact` don't trip the detector, while real
  names (`john` word-rank 372, `smith` 1282) sit below the cutoff and still count.
  Tested: using a broad 5k list wrongly cancelled real names; top-300 fixed it.

## Regenerate
```
# surnames (top 10k):  Names_2010Census.csv  -> lowercase first column, drop "ALL OTHER NAMES"
# given names:         dominictarr first-names.txt -> lowercase unique
# common words:        google-10000-english-usa.txt -> top 5000 lowercase
```
See repo history / docs/name-detection-design.md for the exact build steps.
