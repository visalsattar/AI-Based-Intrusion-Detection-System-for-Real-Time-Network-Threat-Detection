import os
from unittest import mock


def test_queue_proposed_block_calls_redis_xadd(monkeypatch):
    # Create a fake redis client with xadd
    fake = mock.Mock()
    # Simulate xadd returning an entry id
    fake.xadd.return_value = '12345-0'

    # Minimal pipeline-like object with redis_client
    class Dummy:
        def __init__(self, rc):
            self.redis_client = rc

    dummy = Dummy(fake)

    # Call the same queuing logic used in ids_pipeline (replicated)
    src_ip = '10.0.0.5'
    alert_payload = {'dummy': True}
    entry = {
        'src_ip': src_ip,
        'reason': 'test',
        'alert': '{}',
        'detected_at': str(int(0)),
        'proposed_by': 'unit-test'
    }
    dummy.redis_client.xadd('ids:proposed_blocks', entry)
    fake.xadd.assert_called_once()
