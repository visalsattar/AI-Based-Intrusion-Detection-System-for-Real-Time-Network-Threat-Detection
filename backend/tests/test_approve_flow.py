import pytest
from unittest import mock
from flask import Flask
import fakeredis
import os

import backend.routes as routes

@pytest.fixture
def app():
    app = Flask(__name__)
    # Use a fakeredis instance for tests
    fake_redis = fakeredis.FakeStrictRedis()
    routes.register_routes(app, redis_client=fake_redis)
    return app

def test_proposed_block_queue_and_approve_flow(app, tmp_path, monkeypatch):
    client = app.test_client()
    redis_client = app.view_functions['list_proposed_blocks'].__closure__[0].cell_contents  # not ideal; instead reuse fakeredis
    # Retrieve the redis client passed in register_routes via calling the route functions' global? Simpler: re-register
    from flask import Flask
    fapp = Flask(__name__)
    fake_redis = fakeredis.FakeStrictRedis()
    routes.register_routes(fapp, redis_client=fake_redis)
    client = fapp.test_client()

    # Prepare admin API key
    os.environ['BACKEND_ADMIN_API_KEY'] = 'testkey'

    # Create a proposed block entry
    entry_id = fake_redis.xadd('ids:proposed_blocks', {
        'src_ip': '10.0.0.5',
        'reason': 'unit-test',
        'alert': '{}',
        'detected_at': str(12345),
        'proposed_by': 'unit-test'
    })

    # First approver (should be pending since default required=2)
    res1 = client.post('/api/approve-block', json={'entry_id': entry_id, 'approver': 'alice'}, headers={'Authorization': 'Bearer testkey'})
    assert res1.status_code in (200,202)
    data1 = res1.get_json()
    assert data1.get('status') in ('pending', 'approved')

    # Monkeypatch block_ip so we don't actually run iptables
    monkeypatch.setattr(routes, 'block_ip', lambda ip: None)

    # Second approver should trigger approval
    res2 = client.post('/api/approve-block', json={'entry_id': entry_id, 'approver': 'bob'}, headers={'Authorization': 'Bearer testkey'})
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert data2.get('status') == 'approved'

    # Check approved_blocks stream has an entry
    approved = fake_redis.xrange('ids:approved_blocks', count=10)
    assert len(approved) >= 1

def test_deny_block(app, monkeypatch):
    from flask import Flask
    fake_redis = fakeredis.FakeStrictRedis()
    fapp = Flask(__name__)
    routes.register_routes(fapp, redis_client=fake_redis)
    client = fapp.test_client()
    os.environ['BACKEND_ADMIN_API_KEY'] = 'testkey'

    entry_id = fake_redis.xadd('ids:proposed_blocks', {
        'src_ip': '10.0.0.6',
        'reason': 'unit-test',
        'alert': '{}',
        'detected_at': str(12345),
        'proposed_by': 'unit-test'
    })

    res = client.post('/api/deny-block', json={'entry_id': entry_id, 'approver': 'alice', 'reason': 'fp'}, headers={'Authorization': 'Bearer testkey'})
    assert res.status_code == 200
    data = res.get_json()
    assert data.get('status') == 'denied'

