\# hyperproxy



A dependency-free, asyncio HTTP/1.1 forward proxy written in pure Python.



\## Features



\- HTTP/1.1 forward proxying with keep-alive

\- HTTPS via `CONNECT` tunneling

\- Correct hop-by-hop header handling (RFC 7230)

\- Chunked, `Content-Length`, and close-delimited bodies

\- WebSocket / `101 Switching Protocols` upgrades

\- Basic proxy authentication

\- Per-IP token-bucket rate limiting

\- Optional SSRF guard for private/loopback targets

\- Upstream connection pooling

\- Admin endpoints: `/healthz`, `/stats`, `/metrics`



\## Quick start



```bash

python3 proxy.py --port 8080 --admin-port 9090 --user me --password secret

```



Then:



```bash

curl -x http://me:secret@127.0.0.1:8080 http://example.com

curl -x http://me:secret@127.0.0.1:8080 https://example.com

curl http://127.0.0.1:9090/stats

```



\## Docker



```bash

docker build -t hyperproxy .

docker run --rm -p 8080:8080 -p 9090:9090 \\

&#x20; -e PROXY\_USER=me -e PROXY\_PASSWORD=secret hyperproxy

```



\## Environment variables



| Var | Meaning |

|---|---|

| `PROXY\_HOST` | Bind address (default `0.0.0.0`) |

| `PROXY\_PORT` | Proxy port (default `8080`) |

| `PROXY\_ADMIN\_PORT` | Admin port (default `0` = disabled) |

| `PROXY\_USER` / `PROXY\_PASSWORD` | Enable Basic proxy auth |

| `PROXY\_RATE\_LIMIT` / `PROXY\_RATE\_BURST` | Requests/sec per IP |



\## License



MIT

