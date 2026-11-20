"""Durable, bounded webhook retries. Delivery is at least once, not exactly once."""
import asyncio
from datetime import timedelta
import json
import logging
import os
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from pymongo import ReturnDocument
from pymongo.errors import PyMongoError
import mongodb as storage

logger = logging.getLogger(__name__)


def webhook_url():
    url = os.getenv('SECURITY_WEBHOOK_URL', '').strip()
    if not url:
        return ''
    parsed = urlparse(url)
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in {'localhost', '127.0.0.1'}):
        raise ValueError('Security webhooks require HTTPS outside localhost')
    return url


def initial_status(incident):
    if incident.get('simulated') or incident.get('severity') not in {'High', 'Critical'}:
        return 'excluded'
    if incident.get('source_mode') == 'replay' and os.getenv('NOTIFY_REPLAY', 'false').lower() != 'true':
        return 'excluded'
    return 'pending' if webhook_url() else 'not_configured'


def deliver_due_notification():
    url = webhook_url()
    if not url:
        return False
    now = storage.utcnow()
    storage.incident_logs.update_many(
        {'notification_status': 'sending', 'notification_attempts': {'$gte': 3}, 'notification_next_attempt': {'$lte': now}},
        {'$set': {'notification_status': 'failed'}})
    incident = storage.incident_logs.find_one_and_update(
        {'notification_status': {'$in': ['pending', 'retrying', 'sending']},
         'notification_next_attempt': {'$lte': now}, 'notification_attempts': {'$lt': 3}},
        {'$set': {'notification_status': 'sending', 'notification_next_attempt': now + timedelta(seconds=30)},
         '$inc': {'notification_attempts': 1}}, return_document=ReturnDocument.AFTER)
    if not incident:
        return False
    text = f"NetShield incident {incident['_id']}: {incident.get('severity')} {incident.get('type')} from {incident.get('source')}"
    request = Request(url, data=json.dumps({'text': text}).encode(), headers={
        'Content-Type': 'application/json', 'Idempotency-Key': str(incident['_id'])}, method='POST')
    try:
        with urlopen(request, timeout=3) as response:
            if not 200 <= response.status < 300:
                raise OSError('Webhook rejected delivery')
        update = {'notification_status': 'sent', 'notification_sent_at': storage.utcnow()}
    except Exception:
        # Do not log webhook URLs or secrets embedded in exception text.
        attempts = incident['notification_attempts']
        update = {'notification_status': 'failed' if attempts >= 3 else 'retrying',
                  'notification_next_attempt': now + timedelta(seconds=2 ** attempts)}
    storage.incident_logs.update_one({'_id': incident['_id']}, {'$set': update})
    return True


async def notification_worker():
    while True:
        try:
            delivered = await asyncio.to_thread(deliver_due_notification)
        except (PyMongoError, ValueError):
            logger.warning('Notification service unavailable; incident delivery remains in storage')
            delivered = False
        await asyncio.sleep(0.1 if delivered else 2)
