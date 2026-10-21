# pkg/cloudapi — everything Shedu sends to the cloud

This package is the whole contract between a Shedu agent and the optional Shedu cloud.
It is public on purpose: if a field is not declared here, the agent does not send it.
Without `CLOUD_KEY` in `/etc/shedu/guard.conf` the agent sends nothing at all.

| Type | When | Fields and why |
|---|---|---|
| `EnrollRequest` | once, `shedu enroll <token>` | `token` (one-time, from the dashboard), `hostname`, `os`, `arch`, `agent_version`: to show the server in the dashboard. |
| `Report` | at start-up, daily, after `shedu check` | exactly what `shedu check --json` prints (`id`, `severity`, `args`, `fix`, `evidence`), the score, the rendered Hebrew and English texts, and the ports reachable from outside (`port`, `proto`, `bind`, process name). |
| `Event` | each alert | the same alert that goes to Telegram, with a unique `uid` so a retry is stored once. |
| `Heartbeat` | every 5 minutes | version, uptime, which watchers run, whether direct Telegram is configured, interface addresses, language. Lets the cloud tell you when a server goes silent. |

Never sent: the process list, the connection table, key material, secret values, shell
history lines (only file names, as in the Telegram alerts today).

The cloud's answers (`EnrollResponse`, `HeartbeatResponse`, `EventsResponse`,
`ErrorResponse`) are display-only data. There is no command channel: the cloud cannot run
anything on your server. `TestNoCommandFields` fails the build if a response field name
looks like an instruction (`command`, `exec`, `run`, `script`).
