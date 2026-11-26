"""Small store-and-forward envelope for opaque end-to-end encrypted payloads."""

from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass

MAX_HOPS = 8


@dataclass
class RelayEnvelope:
    packet_id: str
    kind: str
    source: str
    destination: str
    hops_left: int
    payload: bytes

    def encode(self) -> bytes:
        return json.dumps({
            "id": self.packet_id,
            "kind": self.kind,
            "source": self.source,
            "destination": self.destination,
            "hops_left": self.hops_left,
            "payload": base64.b64encode(self.payload).decode("ascii"),
        }, separators=(",", ":")).encode("utf-8")

    @classmethod
    def create(
        cls,
        kind: str,
        source: str,
        destination: str,
        payload: bytes,
        packet_id: str | None = None,
    ) -> "RelayEnvelope":
        return cls(packet_id or str(uuid.uuid4()), kind, source, destination, MAX_HOPS, payload)

    @classmethod
    def decode(cls, raw: bytes) -> "RelayEnvelope":
        data = json.loads(raw.decode("utf-8"))
        envelope = cls(
            packet_id=data["id"],
            kind=data["kind"],
            source=data["source"],
            destination=data["destination"],
            hops_left=data["hops_left"],
            payload=base64.b64decode(data["payload"], validate=True),
        )
        if (
            not isinstance(envelope.packet_id, str)
            or envelope.kind not in {"message", "ack"}
            or not 1 <= len(envelope.packet_id) <= 64
            or len(envelope.source) != 64
            or len(envelope.destination) != 64
            or not 0 <= envelope.hops_left <= MAX_HOPS
            or len(envelope.payload) > 48_000
        ):
            raise ValueError("Invalid relay envelope")
        if envelope.kind == "message" and len(envelope.packet_id) != 64:
            raise ValueError("Invalid relayed message ID")
        if envelope.kind == "message":
            bytes.fromhex(envelope.packet_id)
        bytes.fromhex(envelope.source)
        bytes.fromhex(envelope.destination)
        return envelope
