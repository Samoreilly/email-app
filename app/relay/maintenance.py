"""Periodic housekeeping: data retention."""

import asyncio
import logging
from datetime import timedelta

from sqlalchemy import delete

from app.db import session_scope, utcnow
from app.models import DeliveryLog, MessageIdMap, WaitlistEntry

log = logging.getLogger(__name__)

LOG_RETENTION = timedelta(days=30)
MSGID_RETENTION = timedelta(days=730)  # threads can be revived after a long time
UNCONFIRMED_WAITLIST_RETENTION = timedelta(days=30)


def purge_old_data() -> None:
    now = utcnow()
    with session_scope() as db:
        db.execute(delete(DeliveryLog).where(DeliveryLog.created_at < now - LOG_RETENTION))
        db.execute(delete(MessageIdMap).where(MessageIdMap.created_at < now - MSGID_RETENTION))
        db.execute(
            delete(WaitlistEntry).where(
                WaitlistEntry.confirmed_at.is_(None),
                WaitlistEntry.created_at < now - UNCONFIRMED_WAITLIST_RETENTION,
            )
        )


async def maintenance_loop() -> None:
    while True:
        try:
            await asyncio.to_thread(purge_old_data)
        except Exception:
            log.exception("maintenance failed")
        await asyncio.sleep(6 * 3600)
