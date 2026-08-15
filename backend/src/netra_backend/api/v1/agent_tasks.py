"""REST Polling Fallback Endpoints for Host Security Agents."""

import time
from datetime import UTC, datetime, timedelta
from typing import List

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netra_backend.database import get_db_session
from netra_backend.logging import get_logger
from netra_backend.models import Device, DeviceCredential, DeviceCredentialStatus, NonceCache
from netra_shared.crypto import construct_canonical_payload, verify_ed25519_signature

logger = get_logger(__name__)

router = APIRouter(prefix="/agent", tags=["Agent Polling Gateway"])


class AgentTaskItem(BaseModel):
    """Pending Task Item Schema for Host Agent."""

    id: str
    tenant_id: str
    capability: str
    parameters: dict
    created_at: str


class AgentTasksResponse(BaseModel):
    """Agent Task Polling Response Envelope."""

    success: bool = True
    tasks: List[AgentTaskItem]


@router.get("/tasks", response_model=AgentTasksResponse)
async def poll_agent_tasks(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    x_netra_device_id: str = Header(..., alias="X-NETRA-Device-ID"),
    x_netra_timestamp: str = Header(..., alias="X-NETRA-Timestamp"),
    x_netra_nonce: str = Header(..., alias="X-NETRA-Nonce"),
    x_netra_request_id: str = Header(..., alias="X-NETRA-Request-ID"),
    x_netra_signature: str = Header(..., alias="X-NETRA-Signature"),
) -> AgentTasksResponse:
    """Fallback HTTP REST polling endpoint for agents to retrieve pending tasks."""
    # 1. Verify Timestamp Window (5-min limit)
    try:
        req_timestamp = float(x_netra_timestamp)
        now_timestamp = time.time()
        if abs(now_timestamp - req_timestamp) > 300:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Expired timestamp window",
            )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid timestamp format",
        ) from exc

    # 2. Lookup Device and active Ed25519 public key
    stmt = (
        select(Device, DeviceCredential.public_key)
        .join(DeviceCredential, Device.id == DeviceCredential.device_id)
        .where(
            Device.id == x_netra_device_id,
            Device.is_paired == True,  # noqa: E712
            DeviceCredential.status == DeviceCredentialStatus.ACTIVE,
        )
    )
    result = await db.execute(stmt)
    row = result.first()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device unauthenticated, unpaired, or revoked",
        )

    device, public_key_hex = row

    # 3. Check NonceCache to prevent replay
    nonce_stmt = select(NonceCache).where(
        NonceCache.device_id == x_netra_device_id,
        NonceCache.nonce == x_netra_nonce,
    )
    nonce_result = await db.execute(nonce_stmt)
    if nonce_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Replay attack detected (duplicate nonce)",
        )

    # 4. Verify Ed25519 Signature against Canonical Payload
    canonical_payload = construct_canonical_payload(
        method="GET",
        path="/api/v1/agent/tasks",
        timestamp=x_netra_timestamp,
        nonce=x_netra_nonce,
        request_id=x_netra_request_id,
        body=b"",
    )

    if not verify_ed25519_signature(public_key_hex, x_netra_signature, canonical_payload):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Ed25519 signature",
        )

    # Record Nonce
    nonce_entry = NonceCache(
        device_id=x_netra_device_id,
        nonce=x_netra_nonce,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    db.add(nonce_entry)

    # Update device heartbeat
    device.last_heartbeat_at = datetime.now(UTC)
    await db.commit()

    logger.info("agent_tasks_polled", device_id=x_netra_device_id)

    # Phase 4 returns empty pending tasks array (Task Queue Engine implemented in Phase 5)
    return AgentTasksResponse(success=True, tasks=[])
