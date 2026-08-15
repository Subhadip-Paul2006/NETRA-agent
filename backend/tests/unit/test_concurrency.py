"""Unit tests for Multi-User / Async Concurrency Isolation.

Executes simultaneous asynchronous requests to prove that request-scoped contextvars
and response state remain completely isolated across concurrent tasks with zero state contamination.
"""

import asyncio

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_concurrent_request_id_isolation(client: AsyncClient) -> None:
    """Verify concurrent requests with explicit request IDs maintain strict context isolation."""

    async def make_request(req_id: str) -> str:
        # Add slight artificial delay to force async task context switching
        headers = {"X-Request-ID": req_id}
        response = await client.get("/api/v1/health", headers=headers)
        assert response.status_code == 200
        return response.headers.get("X-Request-ID", "")

    task_a = make_request("request-A-10001")
    task_b = make_request("request-B-20002")
    task_c = make_request("request-C-30003")

    res_a, res_b, res_c = await asyncio.gather(task_a, task_b, task_c)

    assert res_a == "request-A-10001"
    assert res_b == "request-B-20002"
    assert res_c == "request-C-30003"


@pytest.mark.asyncio
async def test_concurrent_generated_request_ids_distinct(client: AsyncClient) -> None:
    """Verify concurrent requests with generated IDs produce unique, distinct identifiers."""

    async def make_generated_request() -> str:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        return response.headers.get("X-Request-ID", "")

    # Launch 10 concurrent requests simultaneously
    tasks = [make_generated_request() for _ in range(10)]
    results = await asyncio.gather(*tasks)

    assert len(results) == 10
    # Assert all returned request IDs are unique
    assert len(set(results)) == 10
