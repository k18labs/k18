# Security

## Reporting a vulnerability

Please do not post suspected vulnerabilities, exploit steps, or proof-of-concept code in a public issue, pull request, or discussion. Report them through [GitHub's private vulnerability reporting form](https://github.com/k18labs/k18/security/advisories/new). Include the affected revision, impact, and steps to reproduce; avoid including real credentials or other people's data.

If the private form is unavailable, contact a repository owner privately and ask for a secure reporting route. Do not use a public issue for vulnerability details.

Maintainers should acknowledge reports privately, keep the reporter updated while investigating, and coordinate a fix and disclosure date with them. Publish a GitHub Security Advisory after a fix is available, unless the reporter and maintainers agree that a different timeline is safer.

## Credits

- [dstroy0](https://github.com/dstroy0): audit of `src/`, 20 findings with fixes
  ([issue 1](https://github.com/k18labs/k18/issues/1)). Fixes in c4d4032 and a2d8893; the rest are answered in the issue.
- Reddit user [datkenny](https://www.reddit.com/user/datkenny/): review aimed at the
  private key ([report](https://pastebin.com/izRBKd02)). Found no key disclosure; noted
  that `oohold` relies on `drain`'s frame limit to bound its copy.
- [Patrick O'Reilly](https://github.com/ohohoreilly): further review aimed at the
  private key.
- [Boltthecat19](https://github.com/Boltthecat19): review aimed at the private key
  ([issue 2](https://github.com/k18labs/k18/issues/2)). Found no key disclosure;
  noted that a response index past the table would send memory beyond it (nothing
  stores one). Its probe of a client that does not read led to a9c37d5: such a client
  is served again when it reads, where it waited for a timer.
- And also thank you to everyone else that had a try on getting the key out!
