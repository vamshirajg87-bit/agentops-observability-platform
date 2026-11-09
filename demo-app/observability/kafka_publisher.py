"""
observability/kafka_publisher.py

Publishes validated canonical AgentOps telemetry events to Kafka.

Publishing is non-blocking for the application path. Delivery success
or failure is handled asynchronously through the Kafka delivery callback.
"""

import logging

from confluent_kafka import Producer

from schemas.telemetry import CanonicalSpanEvent


logger = logging.getLogger(__name__)

DEFAULT_BOOTSTRAP_SERVERS = "localhost:9092"
DEFAULT_TOPIC = "agentops.telemetry.spans"


class KafkaTelemetryPublisher:
    def __init__(
        self,
        bootstrap_servers: str = DEFAULT_BOOTSTRAP_SERVERS,
        topic: str = DEFAULT_TOPIC,
    ):
        self.topic = topic

        self.producer = Producer(
            {
                "bootstrap.servers": bootstrap_servers,
                "message.timeout.ms": 5000,
            }
        )

    @staticmethod
    def _delivery_report(err, msg):
        if err is not None:
            logger.error(
                "Kafka delivery failed for topic %s: %s",
                msg.topic(),
                err,
            )

    def publish(self, event: CanonicalSpanEvent) -> None:
        try:
            self.producer.produce(
                topic=self.topic,
                key=event.trace_id,
                value=event.model_dump_json(),
                on_delivery=self._delivery_report,
            )

            # Allows librdkafka to process delivery callbacks
            # without blocking the application.
            self.producer.poll(0)

        except BufferError as exc:
            logger.error(
                "Kafka producer queue is full; telemetry event dropped: %s",
                exc,
            )

        except Exception as exc:
            logger.error(
                "Unexpected Kafka publish error: %s",
                exc,
            )

    def flush(self, timeout: float = 5.0) -> int:
        return self.producer.flush(timeout=timeout)