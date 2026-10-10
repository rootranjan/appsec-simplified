# AppSec Simplified

Application security in simple words: analogy, attack, vulnerable code, fix.
Notes are paired with PortSwigger labs, OWASP cheat sheets and YouTube videos.

Site: https://rootranjan.github.io/appsec-simplified/

## Run locally
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
mkdocs serve
```

## Add a topic
Copy `templates/topic.md` into the right `docs/<section>/` folder, then add it to `nav` in `mkdocs.yml` and to `docs/cheatsheet-index.md`.

## Credits and ethics
Defensive guidance builds on the [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) (CC BY-SA 4.0). Notes are in my own words; lab solutions are not republished. Practice only on legal targets.
