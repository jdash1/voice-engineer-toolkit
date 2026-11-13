import contextlib
import io
import ssl
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from voice_toolkit.__main__ import dialplan, sip_summary, latency, certificate, main

class ToolkitTests(unittest.TestCase):
    def test_partition_duplicate_overlap(self):
        rows = [{'extension': '0001'}, {'extension': '0001'}, {'extension': '0000-0009'}, {'extension': '0001', 'partition': 'Lab'}]
        self.assertEqual([x['type'] for x in dialplan(rows)['issues']], ['duplicate', 'overlap', 'overlap'])

    def test_invalid_extensions(self):
        self.assertEqual(dialplan([{'extension': x} for x in ['', '１２３４', '123', '2000-1000', '1XXX']])['issue_count'], 5)

    def test_sip_counts_method_and_retransmissions(self):
        text = 'SIP/2.0 200 OK\ni: abc\nCSeq: 1 OPTIONS\n\n'
        result = sip_summary(text * 2)
        self.assertEqual(result['calls']['abc']['response_methods']['200 OPTIONS'], 2)
        self.assertNotIn('connected', result['calls']['abc'])

    def test_sip_missing_id(self):
        self.assertTrue(sip_summary('SIP/2.0 486 Busy\n\n')['warnings'])
        self.assertEqual(sip_summary('nonsense')['call_ids'], 0)

    def row(self):
        return dict(turn_id='one', speech_end='2026-01-01T00:00:00Z', transcript_final='2026-01-01T00:00:00.2Z', llm_first_token='2026-01-01T00:00:00.6Z', tts_first_audio='2026-01-01T00:00:00.85Z')

    def test_latency(self):
        result = latency([self.row()])
        self.assertEqual(result['summary']['total_response_ms']['p95'], 850)
        self.assertEqual(result['turns'][0]['ai_response_ms'], 400)

    def test_bad_turns(self):
        row = self.row()
        self.assertEqual(len(latency([row, row])['issues']), 1)
        row['speech_end'] = '2026-01-01T00:00:00'
        self.assertEqual(latency([row])['valid_turns'], 0)
        row = self.row()
        row['transcript_final'] = '2025-01-01T00:00:00Z'
        self.assertEqual(latency([row])['valid_turns'], 0)

    @patch('voice_toolkit.__main__.socket.create_connection')
    @patch('voice_toolkit.__main__.ssl.create_default_context')
    def test_tls(self, context, connection):
        secure = context.return_value.wrap_socket.return_value.__enter__.return_value
        secure.getpeercert.return_value = {'notAfter': (datetime.now(timezone.utc) + timedelta(days=5)).strftime('%b %d %H:%M:%S %Y GMT')}
        self.assertEqual(certificate('voice.lab.invalid')['status'], 'expiring')
        self.assertEqual(context.return_value.wrap_socket.call_args.kwargs['server_hostname'], 'voice.lab.invalid')

    @patch('voice_toolkit.__main__.certificate', side_effect=ssl.SSLCertVerificationError('hostname mismatch'))
    def test_tls_failure(self, check):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['cert', 'voice.lab.invalid']), 2)

    def test_missing_file(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['dialplan', 'missing.csv']), 2)
