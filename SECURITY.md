# Security

## Reporting a vulnerability

Email **security@freecore.org**. Please do not open a public issue for a
security problem.

Include what you need to make it reproducible: affected version, the surface
involved, and the steps. If a fix ships, the release notes will credit you
unless you ask otherwise.

## Scope

FreeCORE carries the TrueNAS CORE 13.3 system forward on FreeBSD. A bug you find
here may originate upstream. If it reproduces on stock TrueNAS CORE 13.3 as
well, it is an upstream issue and is best reported to iXsystems — say so in your
report either way and we will sort it out.

## Update integrity

FreeCORE update manifests are signed. The signing anchor ships inside the image
and updates are served from `updates.freecore.org`. An update whose manifest does
not verify against the embedded anchor is refused by the updater.

If you find a way to make the updater accept an unsigned or wrongly-signed
manifest, that is the highest-severity report this project can receive — send it
to the address above.

Security details are published only when doing so no longer creates avoidable
risk for systems that have not yet updated. Public release history can therefore
use neutral maintenance wording without identifying an undisclosed report.

## What this project is

FreeCORE is maintained by a small independent project. There is no commercial
support contract behind it. Treat response times accordingly, and do not run it
anywhere the honest answer to "who fixes this at 3am" matters to you.
