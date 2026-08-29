---
# backend/src/ids_pipeline.py
*** Begin Patch
*** Update File: backend/src/ids_pipeline.py
@@
-            if auto_block_enabled and severity == 'CRITICAL' and src_ip not in whitelist:
-                try:
-                    block_ip(src_ip)
-                except Exception as e:
-                    logger.error(f"Failed to block IP: {e}")
+            if auto_block_enabled and severity == 'CRITICAL' and src_ip not in whitelist:
+                try:
+                    # Instead of blocking immediately, queue a proposed block for operator review.
+                    # This prevents destructive automatic blocking and creates an auditable approval flow.
+                    if self.redis_client:
+                        entry = {
+                            'src_ip': src_ip,
+                            'reason': override_reason or 'anomaly',
+                            'alert': json.dumps(alert_payload),
+                            'detected_at': str(int(time.time())),
+                            'proposed_by': 'auto-detector'
+                        }
+                        try:
+                            entry_id = self.redis_client.xadd('ids:proposed_blocks', entry)
+                            logger.warning(f"Proposed block queued {entry_id} for {src_ip} (requires approval).")
+                        except Exception as e:
+                            logger.error(f"Failed to queue proposed block for {src_ip}: {e}")
+                    else:
+                        logger.warning("Redis unavailable: cannot queue proposed block; not blocking automatically.")
+                except Exception as e:
+                    logger.error(f"Failed to queue/handle proposed block for IP: {e}")
*** End Patch
