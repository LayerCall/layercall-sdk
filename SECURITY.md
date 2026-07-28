# Reporting a security issue

Email **support@layercall.com** with "SECURITY" in the subject. Please do not
open a public issue for anything exploitable — we would rather fix it before it
is public, and so would the people using LayerCall.

Tell us what you did, what happened, and roughly how bad you think it is. A
proof of concept helps but is not required; a clear description of the flaw is
worth more than a working exploit we cannot reproduce.

We will confirm receipt within two working days and tell you what we intend to
do. LayerCall is currently run by one person, so we cannot promise same-day
fixes, but we will not leave you without an answer.

## Scope

**In scope** — this repository, the published `layercall` packages on npm and
PyPI, and the API at `www.layercall.com`.

**Please avoid** — automated scanning that degrades the service for others,
denial of service, social engineering, and anything touching another customer's
data. If a proof of concept needs real customer data to demonstrate, describe
it instead and we will reproduce it ourselves.

## What we consider a real issue

Anything that lets one account read or affect another's data; authentication or
quota bypass; a way to make the API act on a URL or value it should refuse;
secrets exposed in a build artifact; or a scoring path that can be manipulated
into penalising an address an attacker chooses. That last one matters to us
more than it might look: a false accusation carried by a shared reputation
network is a harm to somebody who did nothing wrong, and we treat it as a
security bug rather than an accuracy bug.

## Credit

We are happy to credit you by name or handle when the fix ships, or to keep you
anonymous. Your choice — tell us which. We do not currently run a paid bounty.
