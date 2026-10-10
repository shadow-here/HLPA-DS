# Third-party components

HLPA-DS is an academic project that integrates the following open-source tools.
Each is used under its own license; please review and comply with those licenses.

- **Cowrie** — SSH/Telnet honeypot. BSD-3-Clause. https://github.com/cowrie/cowrie
- **OpenCanary** — multi-service honeypot. BSD-3-Clause. https://github.com/thinkst/opencanary
- **MongoDB** — database (official `mongo` image). SSPL. https://www.mongodb.com
- **Express, React, Vite, Tailwind CSS, nginx** and other packages — see each
  component's `package.json` / image for versions and licenses.

The HTTP decoy, collector/detection engine, API, dashboard, controller, sample
generator and documentation in this repository are original project work.

Reference guidance (verify versions against what you deploy):
- Cowrie docs — https://docs.cowrie.org/en/stable/README.html
- OpenCanary docs — https://docs.opencanary.org/en/latest/
- Suricata EVE JSON (optional) — https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- MITRE ATT&CK — https://attack.mitre.org/
- OWASP Logging Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

## Project license

This project is provided for educational use. Add your institution's or team's
preferred license here before distributing.
