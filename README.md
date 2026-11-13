# Voice Engineer Toolkit

Four small, read-only command-line tools for voice engineers moving into Voice AI. Python 3.10+; no third-party packages. Reports are JSON. All examples are synthetic.

## Quick start

```bash
git clone https://github.com/jdash1/voice-engineer-toolkit.git
cd voice-engineer-toolkit
python3 -m voice_toolkit --help
python3 -m voice_toolkit dialplan examples/dialplan.csv
python3 -m voice_toolkit sip examples/sip.txt
python3 -m voice_toolkit latency examples/latency.csv
python3 -m voice_toolkit cert your-voice-server.example --port 5061
python3 -m unittest discover -s tests -v
```

Run from the repository directory. Private repositories require your normal GitHub authentication to clone.

## Dial Plan Checker

CSV requires `extension`; optional `partition` and `description`. Supports literal ASCII numeric extensions (`1001`) and inclusive ranges (`1000-1099`), four digits per endpoint by default. Use `--length 5` for five digits. Blank partitions use `default`. Finds duplicate numbers, range overlaps within the same partition, invalid formats, and reversed ranges. Leading zeros are validated before numeric comparisons.

The sample deliberately has four findings. Overlap is a review finding, not proof of misconfiguration. This is not a CUCM route-pattern/CSS simulator: no wildcards, translation rules, route precedence, or reachability analysis. Pairwise comparison is intended for small plans.

## SIP Log Summarizer

Input is UTF-8 plain text with SIP request/status lines at column one followed by headers, as in `examples/sip.txt`. Groups by Call-ID (including compact `i` headers), counts requests/responses and response-code/CSeq-method pairs. Header names are case-insensitive. Missing Call-ID messages are skipped with warnings.

Counts include retransmissions. A 200 response may belong to OPTIONS, REGISTER, or BYE; it does not establish an answered call. Authentication challenges are not automatically classified as failures. No PCAP, vendor-prefixed SDL/SDI traces, folded headers, dialog/fork reconstruction, audio quality, or root-cause diagnosis is supported in this initial parser.

## Voice Certificate Checker

```bash
python3 -m voice_toolkit cert cucm.lab.example --port 8443
python3 -m voice_toolkit cert sbc.lab.example --port 5061 --warn-days 45
python3 -m voice_toolkit cert cucm.lab.example --port 8443 --ca-file /path/to/internal-ca.pem
```

Makes a direct TLS connection with SNI, hostname verification, and trusted-chain validation. Reports leaf certificate expiry, issuer, subject, and negotiated TLS version. Defaults: port 5061, timeout 5 seconds, warning within 30 days. Use the service's actual TLS port. Internal PKI requires its trusted PEM CA bundle; no verification bypass is offered.

Invalid/expired/untrusted certificates produce an error rather than unverified expiry data. This is not a SIP OPTIONS probe, revocation checker, complete chain inventory, STARTTLS or mutual-TLS client, or application health check. Only test authorized endpoints. Unit tests mock TLS; live endpoint interoperability has not been tested here.

## Voice AI Latency Analyzer

One CSV row per unique `turn_id`, with timezone-aware ISO-8601 timestamps:

| Column | Meaning |
|---|---|
| `speech_end` | Caller finishes speaking |
| `transcript_final` | Final transcript available |
| `llm_first_token` | First AI response token available |
| `tts_first_audio` | First generated audio chunk available |

Reports adjacent stage durations and total response time (speech end to first generated audio), plus mean, p50, p95, and maximum. Percentiles use nearest rank. Sample totals: 850 and 1100 ms. Duplicate IDs, missing/invalid timestamps, and reversed stages produce findings. No missing timings are imputed.

These are observed intervals, including orchestration delays. Streaming stages may overlap and require a different event model. First generated audio is not caller playback: network, buffering, and telephony playout delay are excluded. Use synchronized clocks.

## Reports, privacy, and exit codes

```bash
mkdir -p reports
python3 -m voice_toolkit latency examples/latency.csv > reports/latency.json
```

- `0`: completed without findings/warnings.
- `1`: findings, parsing warnings, certificate expiry warning, or no valid latency turns.
- `2`: input, network, TLS, or command usage error.

An empty dial-plan CSV with valid headers returns zero records. Only `cert` opens a network connection. No uploads or telemetry. Keep customer exports, actual call traces, credentials, and keys outside Git, including while private: commit history remains when made public.

## Next improvements

Vendor-specific SIP log adapters, configurable number-pattern rules, batch certificate inventory, and streaming Voice AI event adapters.
