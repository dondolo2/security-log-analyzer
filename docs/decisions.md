# Design decisions

Every non-trivial choice in this repo has an answer here. If a reviewer
asks "why this design?", this document is the answer.

---

## 1. Why SQLite over Postgres?

Same reasoning as the DE project: single-writer, small dataset, and the
demo has to run with `docker compose up` and nothing else. A Postgres
container is a moving part that adds zero value to a project whose data
volume is a handful of log lines per second at most.

The storage layer is deliberately abstracted behind `analyzer.storage.db`.
Swapping to Postgres is a connection-string change and a `pip install
psycopg` — the SQL is already ANSI-ish and the schema uses nothing
SQLite-specific beyond `AUTOINCREMENT`.

## 2. Why generate synthetic logs instead of ingesting real ones?

Real log formats (syslog, Windows Event Log, nginx, JSON-lines from
Kubernetes) each require a dedicated parser. Writing three half-working
parsers would demonstrate less skill than one working parser plus a
detector with boundary tests.

More importantly: **synthetic logs come with ground truth.** I know
exactly which lines should fire alerts. Real logs don't — I'd be
eyeballing output and calling it "correct". The generator produces four
scenarios (brute force, account attack, normal, borderline) and
`sample_logs/expected_alerts.json` states what detection must produce.

Adding a real parser is a `parser/` module with the same contract
(`raw line -> dict | None`). The architecture supports it; I just didn't
need to prove it.

## 3. Why config-file thresholds instead of constants?

Because a detection rule whose sensitivity can't be tuned is security
theatre. A real analyst needs to answer "how many failed logins in how
many minutes?" without a code change and a redeploy. `config/detection.yaml`
is the tuning surface; the code reads it once at startup.

This also makes tests simpler — tests construct config dicts directly,
they don't monkeypatch module constants.

## 4. Why three rules and not ten?

Three well-tested rules with explicit boundary tests demonstrate more
than ten that only handle the happy path. Every rule here has at least
one test proving it *doesn't* fire on a borderline case, which is the
test that actually matters in security tooling.

The three rules were chosen because they cover three distinct shapes:
- Brute force: one IP, one user, high frequency.
- Account attack: one IP, many users, medium frequency.
- Suspicious login: failure burst followed by success (state transition).

Adding a fourth rule that shares a shape with an existing one is
repetition, not coverage.

## 5. What is a false positive here, and how would I reduce them?

The clearest one: **suspicious login.** A user mistypes their password
three times and then logs in successfully. That's indistinguishable from
"attacker tried passwords, then succeeded" using only log data.

Reductions, in order of cost:
- Raise `failure_burst_threshold` — cheap, but a slow attacker evades.
- Require a short interval between the last failure and the success —
  the typo case usually has the success within seconds; a real attacker
  is often slower. Costs nothing, catches the common case.
- Correlate with source: is the IP known for this user? (Out of scope;
  requires state this project doesn't have.)

I have implemented (2) implicitly by tying the rule to the lookback
window; I have not implemented (3).

## 6. What is a false negative here, and how would I catch it?

**Slow-and-low.** An attacker spreading five failures across three hours
evades the brute-force rule entirely — the time window is 2 minutes.
This is the classic tradeoff: shorter window = fewer false positives,
more false negatives.

Catching slow-and-low properly needs a rate over a longer horizon
(e.g. >20 failures/day from one IP) which is a *different rule*, not a
tuning change. It's listed in Future Improvements.

Second false negative: **distributed brute force.** One user, many IPs,
one failure each. Neither rule catches it. Again: different rule.

## 7. Why is the alert idempotency key `(alert_type, ip, username, first_seen)`?

Re-running detection on the same log file must not duplicate alerts.
If I run the pipeline twice over the same input, I should still see
one alert, not two.

But if the *same attacker* attacks the *same target* two hours later,
that's a genuinely new incident and should produce a new alert. The
`first_seen` component of the key distinguishes these: a re-run computes
the same `first_seen` (deterministic from the input), a new attack
computes a different one.

`alert_type` and `ip_address`/`username` distinguish the three rules
from each other — a brute-force and a suspicious-login alert from the
same IP at the same moment are two events, not a collision.V

---

## Open questions (to resolve on later days)

- [ ] Should `suspicious_login` require the success within N seconds of
      the last failure, or only within the lookback window? (Day 8)
- [ ] Dashboard: which two charts per tab? Keep it to two. (Day 9)
- [ ] Docker: does the dashboard run in the same container as the CLI,
      or split? (Day 9-10)