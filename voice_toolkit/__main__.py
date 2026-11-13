"""Run with python3 -m voice_toolkit --help."""
import argparse
import csv
import json
import math
import re
import socket
import ssl
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def read_csv(path, required):
    with open(path, newline='', encoding='utf-8-sig') as stream:
        reader = csv.DictReader(stream)
        if not required.issubset(set(reader.fieldnames or [])):
            raise ValueError('CSV requires columns: ' + ', '.join(sorted(required)))
        return list(reader)


def dialplan(rows, length=4):
    """Validate literal extensions and inclusive numeric ranges, scoped by partition."""
    issues, intervals = [], []
    for number, row in enumerate(rows, 2):
        value = (row.get('extension') or '').strip()
        partition = (row.get('partition') or 'default').strip() or 'default'
        parts = value.split('-')
        if len(parts) not in (1, 2) or any(not re.fullmatch(r'[0-9]{%d}' % length, p) for p in parts):
            issues.append({'row': number, 'type': 'invalid_format', 'value': value})
            continue
        start, end = int(parts[0]), int(parts[-1])
        if start > end:
            issues.append({'row': number, 'type': 'reversed_range', 'value': value})
            continue
        for old_start, old_end, old_row, old_part in intervals:
            if partition == old_part and max(start, old_start) <= min(end, old_end):
                issues.append({'row': number, 'other_row': old_row,
                               'type': 'duplicate' if start == end == old_start == old_end else 'overlap',
                               'partition': partition, 'value': value})
        intervals.append((start, end, number, partition))
    return {'records': len(rows), 'issue_count': len(issues), 'issues': issues}


def sip_summary(text):
    """Parse plain SIP message starts and headers, not packet captures or vendor prefixes."""
    starts = re.compile(r'^(?:SIP/2\.0 [1-6][0-9]{2}(?:\s|$)|[A-Z]+\s+\S+\s+SIP/2\.0\s*$)')
    calls, warnings = {}, []
    block, line_number = [], 0

    def consume(lines, number):
        if not lines:
            return
        headers = {}
        for line in lines[1:]:
            if not line.strip():
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        call_id = headers.get('call-id') or headers.get('i')
        if not call_id:
            warnings.append(f'Message at line {number}: missing Call-ID; skipped')
            return
        call = calls.setdefault(call_id, {'messages': 0, 'requests': Counter(), 'responses': Counter(), 'response_methods': Counter()})
        call['messages'] += 1
        if lines[0].startswith('SIP/2.0 '):
            code = lines[0].split()[1]
            call['responses'][code] += 1
            method = headers.get('cseq', '').split()
            call['response_methods'][f'{code} {method[-1] if len(method) == 2 else "UNKNOWN"}'] += 1
        else:
            call['requests'][lines[0].split()[0]] += 1
    for index, line in enumerate(text.splitlines(), 1):
        if starts.match(line):
            consume(block, line_number)
            block, line_number = [line], index
        elif block:
            block.append(line)
    consume(block, line_number)
    if not calls:
        warnings.append('No supported messages with Call-ID found')
    return {'call_ids': len(calls), 'calls': calls, 'warnings': warnings,
            'note': 'Counts include retransmissions. Responses alone do not establish call outcome or media quality.'}


STAGES = [('transcription_ms', 'speech_end', 'transcript_final'),
          ('ai_response_ms', 'transcript_final', 'llm_first_token'),
          ('speech_generation_ms', 'llm_first_token', 'tts_first_audio'),
          ('total_response_ms', 'speech_end', 'tts_first_audio')]


def percentile(values, fraction):
    values = sorted(values)
    return values[max(0, math.ceil(len(values) * fraction) - 1)]


def latency(rows):
    """Each CSV row represents one turn, with timezone-aware ISO-8601 timestamps."""
    turns, issues = [], []
    seen = set()
    for number, row in enumerate(rows, 2):
        turn_id = (row.get('turn_id') or '').strip()
        if not turn_id or turn_id in seen:
            issues.append({'row': number, 'error': 'Missing or duplicate turn_id'})
            continue
        seen.add(turn_id)
        try:
            times = {}
            for event in ('speech_end', 'transcript_final', 'llm_first_token', 'tts_first_audio'):
                value = datetime.fromisoformat(row[event].strip().replace('Z', '+00:00'))
                if value.utcoffset() is None:
                    raise ValueError('Timestamps must include timezone offsets')
                times[event] = value
            result = {'turn_id': turn_id}
            for metric, start, end in STAGES:
                delta = (times[end] - times[start]).total_seconds() * 1000
                if delta < 0:
                    raise ValueError('Events are out of chronological order')
                result[metric] = round(delta, 3)
            turns.append(result)
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            issues.append({'row': number, 'error': str(error)})
    aggregates = {}
    for metric, _, _ in STAGES:
        values = [turn[metric] for turn in turns]
        if values:
            aggregates[metric] = {'mean': round(sum(values) / len(values), 3),
                                  'p50': percentile(values, .5), 'p95': percentile(values, .95), 'max': max(values)}
    return {'valid_turns': len(turns), 'issues': issues, 'summary': aggregates, 'turns': turns}


def certificate(host, port=5061, timeout=5, warn_days=30, cafile=None):
    """Perform a verified direct TLS handshake; never disable verification."""
    context = ssl.create_default_context(cafile=cafile)
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as secure:
            cert = secure.getpeercert()
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']), timezone.utc)
            days = (expires - datetime.now(timezone.utc)).total_seconds() / 86400
            return {'host': host, 'port': port, 'verified': True, 'tls_version': secure.version(),
                    'expires_at': expires.isoformat(), 'days_remaining': round(days, 2),
                    'status': 'expiring' if days <= warn_days else 'ok',
                    'subject': cert.get('subject'), 'issuer': cert.get('issuer')}


def positive(value):
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError('Must be a positive integer')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Voice Engineer Toolkit — JSON reports, Python standard library only')
    commands = parser.add_subparsers(dest='command', required=True)
    dial = commands.add_parser('dialplan', help='Check literal extension/range CSV')
    dial.add_argument('file', type=Path)
    dial.add_argument('--length', type=positive, default=4)
    sip = commands.add_parser('sip', help='Summarize plain SIP text')
    sip.add_argument('file', type=Path)
    timing = commands.add_parser('latency', help='Analyze per-turn timestamp CSV')
    timing.add_argument('file', type=Path)
    tls = commands.add_parser('cert', help='Verify a direct TLS endpoint')
    tls.add_argument('host')
    tls.add_argument('--port', type=positive, default=5061)
    tls.add_argument('--timeout', type=positive, default=5)
    tls.add_argument('--warn-days', type=positive, default=30)
    tls.add_argument('--ca-file', help='PEM CA bundle for internal certificates')
    args = parser.parse_args(argv)
    try:
        if args.command == 'dialplan':
            report = dialplan(read_csv(args.file, {'extension'}), args.length)
            status = bool(report['issues'])
        elif args.command == 'sip':
            report = sip_summary(args.file.read_text(encoding='utf-8-sig'))
            status = bool(report['warnings'])
        elif args.command == 'latency':
            report = latency(read_csv(args.file, {'turn_id', 'speech_end', 'transcript_final', 'llm_first_token', 'tts_first_audio'}))
            status = bool(report['issues']) or not report['valid_turns']
        else:
            if args.port > 65535:
                raise ValueError('Port must be between 1 and 65535')
            report = certificate(args.host, args.port, args.timeout, args.warn_days, args.ca_file)
            status = report['status'] != 'ok'
        print(json.dumps(report, indent=2))
        return int(status)
    except (OSError, ValueError, csv.Error, UnicodeError) as error:
        print(json.dumps({'error': str(error)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
