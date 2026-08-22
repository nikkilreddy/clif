"""Protocol-neutral ingestion adapter for SIEM and custom integrations."""

from datetime import datetime, timezone
import os
from typing import Any
from uuid import uuid4

from confluent_kafka import Producer
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "redpanda01:9092")
DEFAULT_TOPIC = os.getenv("DEFAULT_TOPIC", "raw-logs")
producer = Producer({"bootstrap.servers": KAFKA_BROKERS})
app = FastAPI(title="Cognitive Log Investigation Platform Ingestion Adapter", version="1.0.0")


class EventSource(BaseModel):
    name: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    tenant: str | None = None


class EventEnvelope(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: EventSource
    event: dict[str, Any]
    context: dict[str, Any] = Field(default_factory=dict)
    trace: dict[str, Any] = Field(default_factory=dict)


def topic_for(envelope: EventEnvelope) -> str:
    """Allow adapters to preserve a known route without coupling agents to it."""
    event_type = envelope.event.get("clif_event_type")
    return event_type if event_type in {"security-events", "process-events", "network-events", "raw-logs"} else DEFAULT_TOPIC


def delivery_error(error, message) -> None:
    if error:
        app.state.last_delivery_error = str(error)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/events", status_code=202)
def ingest(envelope: EventEnvelope) -> dict[str, str]:
    payload = envelope.model_dump(mode="json")
    event = payload["event"]
    event.update(
        {
            "event_id": envelope.event_id,
            "timestamp": payload["observed_at"],
            "integration": envelope.source.name,
            "source_kind": envelope.source.kind,
        }
    )
    try:
        producer.produce(topic_for(envelope), value=__import__("json").dumps(event), callback=delivery_error)
        producer.poll(0)
    except BufferError as exc:
        producer.poll(1)
        raise HTTPException(status_code=503, detail="ingestion buffer is full") from exc
    return {"event_id": envelope.event_id, "status": "accepted"}
