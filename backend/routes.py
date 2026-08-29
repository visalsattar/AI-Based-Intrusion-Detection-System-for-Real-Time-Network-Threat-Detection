*** Begin Patch
*** Update File: backend/routes.py
@@
 from geo_utils import get_ip_location, reload_reader
 import geo_utils
 from network_utils import list_interfaces, list_arp_devices
 from system_status import get_full_status
 import threat_intel_service
+import os
+import time
+from flask import abort
+from ids_pipeline import block_ip
@@
     @app.route('/api/settings', methods=['GET'])
     def get_settings():
@@
         return jsonify(settings)
@@
     @app.route('/api/save-settings', methods=['POST'])
     def save_settings():
@@
         return jsonify({'status': 'success', 'message': 'Configuration updated'})
+
+    # ---------------- Proposed block / approval workflow ----------------
+    @app.route('/api/proposed-blocks', methods=['GET'])
+    def list_proposed_blocks():
+        """List recent proposed blocks from the ids:proposed_blocks Redis stream."""
+        if not redis_client:
+            return jsonify({'status': 'error', 'message': 'Redis unavailable'}), 503
+        count = int(request.args.get('count', 100))
+        try:
+            raw = redis_client.xrevrange('ids:proposed_blocks', count=count)
+            entries = []
+            for msg_id, fields in raw:
+                # fields are bytes/strings depending on client; ensure strings
+                entry = {k.decode() if isinstance(k, bytes) else k: (v.decode() if isinstance(v, bytes) else v) for k, v in fields.items()}
+                entries.append({'id': msg_id, 'data': entry})
+            return jsonify({'count': len(entries), 'entries': entries})
+        except Exception as e:
+            logger.error(f"Failed to read proposed blocks: {e}")
+            return jsonify({'status': 'error', 'message': str(e)}), 500
+
+    def _require_admin_api_key():
+        key = os.environ.get('BACKEND_ADMIN_API_KEY')
+        if not key:
+            # No API key configured -> deny by default
+            abort(403, "Admin API key not configured on server")
+        auth = request.headers.get('Authorization','')
+        if not auth.startswith('Bearer '):
+            abort(401, 'Missing bearer token')
+        token = auth.split(' ',1)[1].strip()
+        if token != key:
+            abort(403, 'Invalid admin API key')
+
+    @app.route('/api/approve-block', methods=['POST'])
+    def approve_block():
+        """Approve a proposed block. Supports multi-approver policy via BLOCK_APPROVAL_REQUIRED."""
+        _require_admin_api_key()
+        payload = request.json or {}
+        entry_id = payload.get('entry_id')
+        approver = payload.get('approver') or 'unknown'
+        if not entry_id:
+            return jsonify({'status': 'error', 'message': 'entry_id required'}), 400
+        if not redis_client:
+            return jsonify({'status': 'error', 'message': 'Redis unavailable'}), 503
+        try:
+            # Read specific entry
+            items = redis_client.xrange('ids:proposed_blocks', min=entry_id, max=entry_id)
+            if not items:
+                return jsonify({'status': 'error', 'message': 'entry not found'}), 404
+            _id, fields = items[0]
+            # normalize fields
+            entry = {k.decode() if isinstance(k, bytes) else k: (v.decode() if isinstance(v, bytes) else v) for k, v in fields.items()}
+            src_ip = entry.get('src_ip')
+
+            # Load whitelist
+            base = os.path.abspath(os.path.join(os.path.dirname(__file__), ''))
+            whitelist_path = os.path.join(base, 'config', 'whitelist.json')
+            whitelist = []
+            try:
+                if os.path.exists(whitelist_path):
+                    with open(whitelist_path) as fh:
+                        import json as _json
+                        whitelist = _json.load(fh)
+            except Exception:
+                whitelist = []
+
+            if src_ip in whitelist:
+                return jsonify({'status': 'error', 'message': 'IP is whitelisted and cannot be auto-blocked'}), 403
+
+            approvals_key = f"proposed:{entry_id}:approvals"
+            redis_client.sadd(approvals_key, approver)
+            count = redis_client.scard(approvals_key)
+            required = int(os.environ.get('BLOCK_APPROVAL_REQUIRED', '2'))
+            if count >= required:
+                # Execute the block and write an approved_blocks stream entry + audit
+                try:
+                    block_ip(src_ip)
+                except Exception as e:
+                    logger.error(f"Failed to execute block_ip for {src_ip}: {e}")
+                    return jsonify({'status': 'error', 'message': f'block failed: {e}'}), 500
+                approved_entry = {
+                    'src_ip': src_ip,
+                    'reason': entry.get('reason',''),
+                    'alert': entry.get('alert',''),
+                    'detected_at': entry.get('detected_at',''),
+                    'approved_by': approver,
+                    'approved_at': str(int(time.time())),
+                    'approval_count': str(count)
+                }
+                try:
+                    redis_client.xadd('ids:approved_blocks', approved_entry)
+                except Exception:
+                    logger.warning('Failed to record approved_blocks stream')
+                # Audit log
+                try:
+                    os.makedirs('logs', exist_ok=True)
+                    with open('logs/blocks.log', 'a') as f:
+                        f.write(f"{int(time.time())} APPROVED {entry_id} src={src_ip} by={approver} count={count}\n")
+                except Exception:
+                    logger.warning('Failed to write audit log for block approval')
+                return jsonify({'status': 'approved', 'approved_by': approver, 'approval_count': count})
+            else:
+                return jsonify({'status': 'pending', 'approval_count': count, 'needed': required - count}), 202
+        except Exception as e:
+            logger.error(f"approve-block error: {e}")
+            return jsonify({'status': 'error', 'message': str(e)}), 500
+
+    @app.route('/api/deny-block', methods=['POST'])
+    def deny_block():
+        _require_admin_api_key()
+        payload = request.json or {}
+        entry_id = payload.get('entry_id')
+        approver = payload.get('approver') or 'unknown'
+        reason = payload.get('reason','manual deny')
+        if not entry_id:
+            return jsonify({'status': 'error', 'message': 'entry_id required'}), 400
+        if not redis_client:
+            return jsonify({'status': 'error', 'message': 'Redis unavailable'}), 503
+        try:
+            # record denial and audit
+            os.makedirs('logs', exist_ok=True)
+            with open('logs/blocks.log', 'a') as f:
+                f.write(f"{int(time.time())} DENIED {entry_id} by={approver} reason={reason}\n")
+            try:
+                redis_client.xadd('ids:denied_blocks', {'entry_id': entry_id, 'denied_by': approver, 'reason': reason, 'time': str(int(time.time()))})
+            except Exception:
+                logger.warning('Failed to record denied_blocks stream')
+            return jsonify({'status': 'denied'})
+        except Exception as e:
+            logger.error(f"deny-block error: {e}")
+            return jsonify({'status': 'error', 'message': str(e)}), 500
*** End Patch
