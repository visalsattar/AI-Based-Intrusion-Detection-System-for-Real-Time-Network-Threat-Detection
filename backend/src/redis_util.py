# backend/src/redis_util.py
"""
Single place that knows how to reach Redis.

main.py and ids_pipeline.py used to build their own clients with different defaults
(host 'localhost' vs 'redis') and a hard-coded port 6379, while docker-compose publishes
Redis on host port 6380. A sniffer running natively on the host (the "local sniffer +
Dockerized dashboard" architecture) therefore could not reach the compose Redis.

Environment:
    REDIS_HOST      default "localhost"   (docker-compose sets it to "redis")
    REDIS_PORT      default 6379          (use 6380 from the host against docker-compose)
    REDIS_PASSWORD  default none
"""
import os

from redis import Redis


def make_redis(**overrides) -> Redis:
    kwargs = dict(
        host=os.environ.get("REDIS_HOST", "localhost"),
        port=int(os.environ.get("REDIS_PORT", "6379")),
        password=os.environ.get("REDIS_PASSWORD") or None,
        decode_responses=True,
        socket_connect_timeout=2,
    )
    kwargs.update(overrides)
    return Redis(**kwargs)
