"""Validated resource budgets; unknown keys and unsafe values are rejected."""

from pathlib import Path
from typing import Annotated

import yaml
from pydantic import BaseModel, ConfigDict, Field

Budget = Annotated[int, Field(strict=True, ge=1, le=1_000_000_000)]


class Limits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    max_packet_length: Budget = 262144
    max_capture_bytes: Budget = 134217728
    max_blocks: Budget = 2000000
    max_packets: Budget = 1000000
    max_flows: Budget = 4096
    max_stream_bytes: Budget = 262144
    max_reassembly_total: Budget = 16777216
    max_headers: Budget = 128
    max_options: Budget = 128
    max_ipv6_extensions: Budget = 16
    max_fragment_buffers: Budget = 256
    max_fragment_bytes: Budget = 4194304
    max_dns_hops: Budget = 32
    max_dns_records: Budget = 256
    max_http_header: Budget = 32768
    max_decompressed_bytes: Budget = 134217728
    max_decompression_ratio: Budget = 100
    max_block_length: Budget = 1048576
    max_interfaces: Budget = 256
    max_warnings: Budget = 1000
    max_metadata: Budget = 10000
    max_metadata_bytes: Budget = 8388608
    max_timing_samples: Budget = 1024
    max_filter_tokens: Budget = 256
    max_filter_depth: Budget = 32
    max_segment_count: Budget = 4096
    max_tls_handshake: Budget = 131072
    fragment_timeout: Budget = 30
    flow_timeout: Budget = 60

    @classmethod
    def load(cls, path: Path | None = None) -> "Limits":
        if path is None:
            return cls()
        if path.stat().st_size > 65536:
            raise ValueError("Limits config exceeds 64 KiB")
        # Configuration is user-controlled, not capture content. SafeLoader only.
        with path.open(encoding="utf-8") as source:
            try:
                value = yaml.safe_load(source)
            except yaml.YAMLError as error:
                raise ValueError("Malformed limits YAML") from error
        return cls.model_validate(value)
