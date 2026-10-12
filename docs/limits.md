# Resource limits and their tests

`configs/limits.yaml` and `Limits` define matching defaults (the equality is
itself tested). CLI `--limits` selects a custom validated YAML. Unknown keys,
booleans masquerading as integers, nonpositive budgets and excessive integers
are rejected. Increasing budgets is a deliberate resource tradeoff, not a promise
that a process will fit every machine. Settings files are user configuration,
not capture content; keep them small and trusted.

| Budget | Default | Why | Dedicated test |
| --- | ---: | --- | --- |
| max_capture_bytes | 134217728 | cap regular input and hash reads | test_options_capture_and_block_caps |
| max_packet_length | 262144 | bound packet allocation | test_packet_and_interface_block_limits |
| max_packets | 1000000 | bound record work | test_packet_and_interface_block_limits |
| max_blocks | 2000000 | prevent section/unknown-block floods | test_no_infinite_section_headers |
| max_block_length | 1048576 | bound PCAPNG reads | test_packet_and_interface_block_limits |
| max_interfaces | 256 | bound interface tables | test_packet_and_interface_block_limits |
| max_flows | 4096 | LRU eviction and bounded talker table | test_flow_timeout_eviction_and_timing_cap, test_talker_and_timeline_caps |
| max_stream_bytes | 262144 | bound a stream's sequence span | test_reassembly_caps |
| max_reassembly_total | 16777216 | bound data plus presence arrays | test_reassembly_caps |
| max_segment_count | 4096 | bound segment/piece bookkeeping | test_reassembly_caps, test_fragment_piece_count |
| max_headers | 128 | bound VLAN/header/record/trailer chains | test_protocol_count_budgets, test_tls_record_count_limit |
| max_options | 128 | bound TLVs/chunks/extension vectors | test_protocol_count_budgets, test_options_capture_and_block_caps |
| max_ipv6_extensions | 16 | stop long extension chains | test_protocol_count_budgets |
| max_fragment_buffers | 256 | bound simultaneous incomplete sets | test_fragment_caps_overlap_and_timeout, test_tiny_fragment_flood |
| max_fragment_bytes | 4194304 | bound fragment payload storage | test_fragment_caps_overlap_and_timeout, test_tiny_fragment_flood |
| max_dns_hops | 32 | bound compression traversal | test_dns_pointer_limit_and_record_budget |
| max_dns_records | 256 | bound questions/records | test_dns_pointer_limit_and_record_budget |
| max_http_header | 32768 | bound header/trailer bytes | test_http_limits_and_gzip |
| max_decompressed_bytes | 134217728 | stop expansion bombs | test_gzip_bomb |
| max_decompression_ratio | 100 | bound amplification | test_gzip_bomb, test_http_limits_and_gzip |
| max_tls_handshake | 131072 | bound fragmented handshake buffers | test_tls_handshake_budget |
| max_warnings | 1000 | retain a sample, count suppressed diagnostics | test_unpack_and_warning_budget, test_tiny_fragment_flood |
| max_metadata | 10000 | bound retained rows and timeline bins | test_retained_metadata_limits, test_talker_and_timeline_caps |
| max_metadata_bytes | 8388608 | bound serialized retained metadata | test_retained_metadata_limits |
| max_timing_samples | 1024 | bound timing evidence per flow | test_flow_timeout_eviction_and_timing_cap |
| max_filter_tokens | 256 | bound filter size and token work | test_filter_limits |
| max_filter_depth | 32 | bound recursive nesting (also hard-capped at 64) | test_filter_limits |
| fragment_timeout | 30 seconds | release stale incomplete datagrams | test_fragment_caps_overlap_and_timeout |
| flow_timeout | 60 seconds | split inactive conversation instances | test_flow_timeout_eviction_and_timing_cap |

Tests are in test_foundations.py, test_formats.py, test_protocols.py,
test_flows.py, test_filters_outputs.py, test_adversarial.py and test_regressions.py.
The 10,000 tiny-fragment flood checks live occupancy/bytes after every insertion,
not just a final count. Separate loop tests verify visited DNS offsets; structured
properties verify valid compression and filter semantics in addition to arbitrary
input rejection.

Serialized metadata budgets and TCP array accounting exclude Python object
headers, tables, allocator fragmentation and renderer copies. Report sampled RSS
separately with psutil. A 2 ms sampling interval can miss shorter-lived peaks;
never present it as an exact instantaneous maximum or extrapolate it to every
capture. Captures are streamed, but reports need bounded retained metadata.

Limits yield recorded warnings or suppression counts. Suppressed metadata and
evicted flow instances can make evidence incomplete; they never authorize a
maliciousness verdict. DNS name length 255, IPv4/TCP minimum headers, option
encodings and sequence-space constants are wire-protocol facts, not tunable caps.
