# DPI Engine (Python) - Deep Packet Inspection System

This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)
12. [Extending the Project](#12-extending-the-project)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:

- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:

```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

This engine inspects **Layer 3, 4 and 7**. Scapy hands us the Layer 2 frame, but the parser deliberately starts at the IP header - see Section 7.

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

A bare TCP SYN in our test capture is exactly `14 + 20 + 20 = 54` bytes, which is why the first parsed packet reports `packet_length: 54`.

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 142.250.185.206 | Where it's going |
| Source Port | 54552 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP | TCP or UDP |

**Why is this important?**

- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

In this project the five-tuple is a **frozen dataclass**, which makes it hashable and therefore usable as a dictionary key:

```python
@dataclass(frozen=True)
class FiveTuple:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
```

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Two Versions

| Version | File | Use Case |
|---------|------|----------|
| V1 (Single-threaded) | `src/dpi_engine.py` | Learning, small captures, full L7 report |
| V2 (Multi-threaded) | `src/v2/pipeline.py` | Larger captures, concurrency demonstration |

Both versions run in a single `python main.py` invocation, over the same input file, so their results can be compared side by side.

---

## 4. File Structure

```
Packet_Analyzer_Python/
├── src/                            # V1: single-threaded engine
│   ├── pcap_reader.py             # PCAP file reading (Scapy rdpcap)
│   ├── packet_parser.py           # IP / TCP / UDP field extraction
│   ├── sni_extractor.py           # TLS Client Hello → SNI (bounds-checked)
│   ├── http_host_extractor.py     # HTTP "Host:" header extraction
│   ├── types.py                   # FiveTuple, Flow, AppType
│   ├── rule_manager.py            # Classification + blocking rules
│   ├── connection_tracker.py      # Flow table, flow-level decisions
│   ├── analyzer.py                # Statistics and the L7 report
│   └── dpi_engine.py              # ★ V1 ORCHESTRATOR ★
│
├── src/v2/                         # V2: multi-threaded engine
│   ├── thread_safe_queue.py       # Producer/consumer queue wrapper
│   ├── flow_balancer.py           # crc32 five-tuple hashing → worker id
│   ├── worker.py                  # One consumer thread
│   ├── worker_pool.py             # N queues + N workers + N processors
│   ├── dpi_processor.py           # Per-worker DPI unit (reuses V1 parts)
│   └── pipeline.py                # ★ V2 ORCHESTRATOR ★
│
├── tests/                          # 30 test modules (V1 + V2)
├── input/test_dpi.pcap             # Sample capture (77 packets)
├── output/                         # Filtered captures land here
├── generate_test_pcap.py           # Creates reproducible test data
├── main.py                         # CLI entry point (runs V1 then V2)
├── requirements.txt                # scapy
└── README.md                       # This file!
```

---

## 5. The Journey of a Packet (Simple Version)

Let's trace a single packet through `src/dpi_engine.py`.

### Step 1: Read PCAP File

```python
from scapy.all import rdpcap

class PcapReader:
    def __init__(self, file_path):
        self.file_path = file_path

    def read_packets(self):
        packets = rdpcap(self.file_path)
        return packets
```

**What happens:**

1. Scapy opens the file and validates the 24-byte global header
2. Every packet record is decoded into a layered Scapy object
3. A list-like `PacketList` is returned

**PCAP File Format:**

```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

**Design note:** the alternative is walking the raw bytes by hand, computing every header offset yourself. Letting Scapy decode the layers removes a whole class of offset bugs, but it costs speed - and `rdpcap` loads the entire capture into memory, so it is not suitable for multi-gigabyte files.

### Step 2: Read Each Packet

```python
for packet in packets:
    parsed_packet = self.parser.parse(packet)
    parsed_packets.append(parsed_packet)
```

**What happens:**

1. Iterating the `PacketList` yields one Scapy packet at a time
2. Each packet is converted into a plain dictionary
3. The loop ends naturally when the list is exhausted

### Step 3: Parse Protocol Headers

```python
class PacketParser:

    def parse(self, packet):
        result = {}
        result["packet_length"] = len(packet)

        if IP in packet:
            result["src_ip"] = packet[IP].src
            result["dst_ip"] = packet[IP].dst

            protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
            protocol_number = packet[IP].proto
            result["protocol"] = protocol_map.get(protocol_number, "UNKNOWN")

        if TCP in packet:
            result["src_port"] = packet[TCP].sport
            result["dst_port"] = packet[TCP].dport
        elif UDP in packet:
            result["src_port"] = packet[UDP].sport
            result["dst_port"] = packet[UDP].dport

        if TCP in packet:
            result["payload"] = bytes(packet[TCP].payload)
        elif UDP in packet:
            result["payload"] = bytes(packet[UDP].payload)

        return result
```

**What happens:**

```
Scapy layers:
Ether / IP / TCP / Raw

After parsing:
parsed["packet_length"] = 54
parsed["src_ip"]        = "192.168.1.100"
parsed["dst_ip"]        = "142.250.185.206"
parsed["protocol"]      = "TCP"
parsed["src_port"]      = 54552
parsed["dst_port"]      = 443
parsed["payload"]       = b""
```

**Two things worth noticing:**

*Every key is optional.* An ARP or IPv6 frame has no `src_ip`, so downstream code must never index the dictionary directly - it uses `.get()` everywhere. This is what allows non-IP packets to be skipped instead of crashing the engine.

*Layer 2 is intentionally not parsed.* `packet_length` includes the 14-byte Ethernet header, but MAC addresses, EtherType, TTL and TCP flags are not extracted, because nothing in the current blocking logic consumes them. They are a deliberate next step, not an oversight.

### Step 4: Create Five-Tuple and Look Up Flow

```python
five_tuple = self.connection_tracker.create_five_tuple(parsed_packet)

# Skip packets that carry no usable IP information.
if five_tuple is None:
    continue
```

```python
def create_five_tuple(self, packet_data):
    src_ip = packet_data.get("src_ip")
    dst_ip = packet_data.get("dst_ip")
    protocol = packet_data.get("protocol")

    if not src_ip or not dst_ip or not protocol:
        return None

    return FiveTuple(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=packet_data.get("src_port", 0),
        dst_port=packet_data.get("dst_port", 0),
        protocol=protocol,
    )
```

**What happens:**

- The flow table is a plain dict: `FiveTuple → Flow`
- Because `FiveTuple` is a frozen dataclass, Python gives us `__hash__` and `__eq__` for free
- `create_five_tuple` returns `None` for anything that is not IP, and the caller skips it
- All packets with the same 5-tuple share the same `Flow` object

### Step 5: Extract SNI (Deep Packet Inspection)

```python
payload = parsed_packet.get("payload", b"")

# Try to extract the SNI from a TLS ClientHello payload.
sni = self.sni_extractor.extract(payload)

# Get the existing flow or create a new flow.
# Pass the SNI so the flow can be classified and blocked.
flow = self.connection_tracker.get_or_create_flow(five_tuple, sni=sni)
```

Inside `get_or_create_flow`:

```python
if five_tuple not in self.flows:
    self.flows[five_tuple] = Flow(five_tuple=five_tuple, sni=sni)

flow = self.flows[five_tuple]
flow.packet_count += 1

# Store SNI when it becomes available
if sni and flow.sni is None:
    flow.sni = sni

# Classify the flow based on its SNI/domain.
if flow.sni:
    flow.app_type = self.rule_manager.classify_domain(flow.sni)

# Apply blocking rules to the flow.
self.apply_blocking_rules(flow)
```

**What happens (in `sni_extractor.py`):**

1. **Check if it's a TLS Client Hello:**
   ```
   Byte 0: Content Type = 0x16 (Handshake) ✓
   Byte 5: Handshake Type = 0x01 (Client Hello) ✓
   ```
2. **Navigate to Extensions:**
   ```
   Skip: Version, Random, Session ID, Cipher Suites, Compression
   ```
3. **Find SNI Extension (type 0x0000):**
   ```
   Extension Type: 0x0000 (SNI)
   Extension Length: N
   SNI List Length: M
   SNI Type: 0x00 (hostname)
   SNI Length: L
   SNI Value: "www.youtube.com"  ← FOUND!
   ```
4. **Map SNI to App Type:**
   ```python
   # In rule_manager.py
   for rule_domain, app_type in self.domain_rules.items():
       if domain == rule_domain or domain.endswith("." + rule_domain):
           return app_type
   return AppType.UNKNOWN
   ```

**Note the matching rule.** The obvious implementation is a substring search - `"youtube" in sni` - but that also matches `notyoutube.com` and `youtube.com.evil.net`. This matcher anchors on a label boundary instead, so `www.youtube.com` matches `youtube.com` while `evilyoutube.com` does not.

### Step 6: Check Blocking Rules

```python
def apply_blocking_rules(self, flow: Flow):

    # Do not undo a previous blocking decision.
    if flow.blocked:
        return

    if self.rule_manager.is_ip_blocked(flow.five_tuple.src_ip):
        flow.blocked = True
        return

    if self.rule_manager.is_app_blocked(flow.app_type):
        flow.blocked = True
        return

    if self.rule_manager.is_domain_blocked(flow.sni):
        flow.blocked = True
        return
```

**What happens:**

- Three independent rule sets are checked in order: source IP, application, domain
- The first match wins and the whole flow is marked blocked
- A blocked flow is never un-blocked, even if a later packet looks harmless

### Step 7: Forward or Drop

```python
if flow.blocked:
    decision = "DROP"
else:
    decision = "FORWARD"

decisions.append(decision)

# Keep only packets that are allowed to pass.
if decision == "FORWARD":
    forwarded_packets.append(packet)
```

The surviving packets are written back out as a real capture, so the result can be opened in Wireshark and diffed against the input:

```python
wrpcap(args.v1_output, [
    packet
    for packet, parsed in zip(packets, parsed_packets)
    if not connection_tracker.is_packet_blocked(parsed)
])
```

### Step 8: Generate Report

After processing all packets:

```python
protocol_statistics = self.analyzer.analyze(parsed_packets)
```

```python
# Count applications based on tracked network flows.
for flow in self.connection_tracker.flows.values():
    app_name = flow.app_type.name if flow.app_type else "UNKNOWN"
    self.application_count[app_name] = self.application_count.get(app_name, 0) + 1

# Build a report of detected SNI and classified applications.
for flow in self.connection_tracker.flows.values():
    if flow.sni:
        self.sni_application_report.append({
            "sni": flow.sni,
            "application": flow.app_type.name,
            "blocked": flow.blocked,
        })
```

The same report is also serialised for machine consumption:

```python
with open("security_report.json", "w") as file:
    json.dump(report, file, indent=4)
```

---

## 6. The Journey of a Packet (Multi-threaded Version)

The multi-threaded version (`src/v2/pipeline.py`) adds **concurrency** on top of the exact same V1 components.

### Architecture Overview

```
                    ┌─────────────────────┐
                    │   Reader (main)     │
                    │  rdpcap + parse     │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │    FlowBalancer     │
                    │ crc32(5-tuple) % N  │
                    └──────────┬──────────┘
                               │
        ┌──────────┬───────────┼───────────┬──────────┐
        ▼          ▼           ▼           ▼          ▼
   ┌────────┐ ┌────────┐  ┌────────┐  ┌────────┐
   │ Queue0 │ │ Queue1 │  │ Queue2 │  │ Queue3 │   ← one queue PER worker
   └───┬────┘ └───┬────┘  └───┬────┘  └───┬────┘
       │          │           │           │
       ▼          ▼           ▼           ▼
   ┌────────┐ ┌────────┐  ┌────────┐  ┌────────┐
   │Worker 0│ │Worker 1│  │Worker 2│  │Worker 3│   ← DPIWorker threads
   │  own   │ │  own   │  │  own   │  │  own   │
   │  flow  │ │  flow  │  │  flow  │  │  flow  │
   │  table │ │  table │  │  table │  │  table │
   └───┬────┘ └───┬────┘  └───┬────┘  └───┬────┘
       │          │           │           │
       └──────────┴─────┬─────┴───────────┘
                        │
                        ▼
            ┌───────────────────────┐
            │  collect results      │
            │  wrpcap(forwarded)    │
            └───────────────────────┘
```

### Why This Design?

1. **One queue per worker, not one shared queue.** A shared queue would hand the same flow to different threads on different packets.
2. **Flow-hash affinity.** `crc32(canonical 5-tuple) % worker_count` guarantees every packet of a connection lands on the same worker.
3. **Per-worker state, therefore no locks.** Because a flow never crosses workers, each worker owns a private `DPIProcessor` → private `ConnectionTracker` → private flow table. There is not a single mutex in the DPI path.

**Why flow affinity matters:**

```
Connection: 192.168.1.100:54552 → 142.250.185.206:443
Packet 1 (SYN):          crc32 → Worker 2
Packet 2 (Client Hello): crc32 → Worker 2  (same worker!)
Packet 3 (server reply): crc32 → Worker 2  (mirrored 5-tuple, still Worker 2!)

All packets of this conversation go to Worker 2.
Worker 2 can track the flow state correctly, without a lock.
```

**Why crc32 and not the built-in `hash()`:**

```python
def get_worker(self, flow: FlowKey) -> int:
    """
    Uses crc32 rather than the built-in hash(). Python randomises
    string hashing per process (PYTHONHASHSEED), so hash() would
    send the same flow to a different worker on every run and
    destroy the flow affinity this class exists to provide.
    """
    flow_key = "|".join(
        str(part)
        for part in flow.canonical()
    ).encode("utf-8")

    return zlib.crc32(flow_key) % self.worker_count
```

`hash("a")` returns a different value in every new Python process. Using it here would still be *correct within one run*, but the packet-to-worker mapping would be unreproducible, so benchmarks and tests could never be compared across runs.

**Direction-independent hashing.** A client→server packet and the server→client reply have mirrored five-tuples. `canonical()` sorts the two endpoints so both directions of a conversation hash to the same worker:

```python
def canonical(self) -> tuple:
    forward = (self.src_ip, self.dst_ip, self.src_port, self.dst_port)
    reverse = (self.dst_ip, self.src_ip, self.dst_port, self.src_port)
    endpoints = min(forward, reverse)
    return (endpoints[0], endpoints[1], endpoints[2], endpoints[3], self.protocol)
```

### Detailed Flow

#### Step 1: Reader (main thread)

```python
packets = self.reader.read_packets()
self.pool.start()

self.skipped_packets = 0

for packet in packets:
    parsed = self.parser.parse(packet)

    # Non-IP packets have no addresses to balance on.
    if not parsed.get("src_ip") or not parsed.get("dst_ip"):
        self.skipped_packets += 1
        continue

    flow = FlowKey(
        src_ip=parsed["src_ip"],
        dst_ip=parsed["dst_ip"],
        src_port=parsed.get("src_port", 0),
        dst_port=parsed.get("dst_port", 0),
        protocol=parsed.get("protocol", "UNKNOWN"),
    )

    self.pool.submit(flow, packet)
```

The reader does a cheap parse only to build the `FlowKey`. The real DPI work is done again inside the worker, on its own private state. `PacketParser` holds no state, so one shared instance is safe here.

#### Step 2: FlowBalancer + submit

```python
def submit(self, flow: FlowKey, item: T) -> int:
    worker_id = self.balancer.get_worker(flow)
    self.queues[worker_id].push(item)
    return worker_id
```

#### Step 3: Worker thread

```python
def _run(self) -> None:
    while not self._stop_event.is_set():

        try:
            item = self.queue.pop(timeout=0.1)
        except Exception:
            continue

        try:
            result = self.processor(item)
            self._results.append(result)
            self._processed_count += 1

        except Exception as error:
            # One malformed packet must not kill the thread. If it
            # did, this worker's queue would never drain again and
            # WorkerPool.wait_until_empty() would block forever.
            self._error_count += 1
            self._last_error = error

        finally:
            self.queue.task_done()
```

Three details that matter more than they look:

- `pop(timeout=0.1)` instead of a blocking `pop()`, so `stop()` is actually observable and the thread can exit
- the `except Exception` branch, so a single bad packet costs one error counter instead of deadlocking the whole pipeline
- `task_done()` in a `finally`, so the queue's join counter stays correct on both the success and the failure path

#### Step 4: Per-worker DPI processing

```python
def process(self, packet: Any) -> dict:
    parsed_packet = self.parser.parse(packet)
    five_tuple = self.connection_tracker.create_five_tuple(parsed_packet)
    flow = self.connection_tracker.get_or_create_flow(five_tuple)

    payload = parsed_packet.get("payload", b"")
    sni = self.sni_extractor.extract(payload)
    http_host = None

    if not sni:
        http_host = self.http_host_extractor.extract(payload)
    domain = sni or http_host

    if domain:
        flow.sni = domain
        flow.app_type = self.connection_tracker.rule_manager.classify_domain(domain)
        self.connection_tracker.apply_blocking_rules(flow)

    self.processed_packets += 1

    return {
        "packet": parsed_packet,
        "raw_packet": packet,
        "flow": flow,
        "sni": sni,
        "http_host": http_host,
        "decision": "DROP" if flow.blocked else "FORWARD",
    }
```

#### Step 5: Drain, collect and write

```python
self.pool.wait_until_empty()
stats = self.pool.get_worker_stats()
results = self.pool.get_results()
errors = self.pool.get_error_stats()

self.pool.stop()
self.pool.join()

forwarded_packets = [
    result["raw_packet"]
    for result in results
    if result["decision"] == "FORWARD"
]

wrpcap(self.output_path, forwarded_packets)
```

`wait_until_empty()` calls `queue.join()` on every queue, so the main thread blocks until the last packet has been processed - only then are the workers stopped. Writing the output happens once, on the main thread, after all workers have finished.

### Thread-Safe Queue

The magic that makes this work:

```python
class ThreadSafeQueue(Generic[T]):

    def __init__(self, maxsize: int = 0):
        self._queue: Queue[T] = Queue(maxsize=maxsize)

    def push(self, item: T) -> None:
        self._queue.put(item)

    def pop(self, timeout: float | None = None) -> T:
        return self._queue.get(timeout=timeout)

    def task_done(self) -> None:
        self._queue.task_done()

    def join(self) -> None:
        self._queue.join()
```

**How it works:**

- Python's `queue.Queue` already implements the mutex plus condition-variable pattern that this would otherwise need by hand
- `push()` / `pop()` are the producer and consumer ends
- `join()` returns only when every pushed item has had a matching `task_done()`
- `maxsize` gives bounded buffering, which is the hook for backpressure if this ever reads from a live interface instead of a file

This class is a thin wrapper on purpose. It exists so the pipeline depends on *our* interface rather than on `queue.Queue` directly, which is what makes a future swap (bounded queue, batching, multiprocessing queue) a one-file change.

### An honest note on the GIL

This is the part most Python DPI write-ups leave out.

CPython holds a **Global Interpreter Lock**, so only one thread executes Python bytecode at a time. DPI is CPU-bound - parsing headers and walking TLS bytes is pure computation. Therefore **this design does not give a CPU-bound speedup over V1**, and it is not claimed to.

What it does give:

- A correct, race-free concurrent architecture: flow affinity, per-worker state, no shared mutable flow table
- Measurable work distribution across workers
- The exact structure needed to get real parallelism later, because the only change required is swapping `threading` for `multiprocessing` - the flow-hash affinity that makes per-worker state safe is precisely what makes process sharding possible

The architecture is the part that transfers. In CPython the speedup has to come from processes rather than threads, and nothing about the design has to change to get there.

### Design decisions in this pipeline

Each of these had a plausible alternative, and the reason for the choice matters more than the choice:

| Decision | Alternative considered | Why this way |
|----------|------------------------|--------------|
| One queue per worker | One shared queue for all workers | A shared queue hands the same flow to different threads on different packets, which destroys flow state |
| Single balancing stage | Two stages: a dispatcher tier feeding a worker tier | With a deterministic hash, an intermediate tier adds a hop and a copy without changing which worker a flow ends up on |
| `crc32` | Built-in `hash()` | `hash()` on strings is salted per process, so the packet-to-worker mapping would change every run |
| Direction-independent hash | Hash the raw five-tuple | Otherwise a request and its reply land on different workers and neither sees the full conversation |
| Per-worker flow table | One shared table behind a lock | Flow affinity already guarantees exclusivity, so the lock would be pure overhead |
| Write output after drain | Dedicated writer thread + output queue | Writing is I/O-bound and happens once; a whole extra thread and queue buys nothing for a file-based capture |

The last one is the honest trade-off: a dedicated writer thread would matter if this were streaming to disk continuously. For an offline capture it is complexity without benefit, so it is not there.

---

## 7. Deep Dive: Each Component

### src/pcap_reader.py

**Purpose:** Read network captures saved by Wireshark

**Key function:**

```python
def read_packets(self):
    packets = rdpcap(self.file_path)
    return packets
```

**Trade-off:** `rdpcap` reads the whole file into memory. For the 77-packet test capture that is irrelevant; for a real capture it is the first thing that would need to become `PcapReader` streaming (Scapy's `sniff(offline=...)`).

### src/packet_parser.py

**Purpose:** Extract protocol fields from a Scapy packet into a plain dict

**Key function:**

```python
def parse(self, packet):
    result = {}
    result["packet_length"] = len(packet)

    if IP in packet:
        ...
    if TCP in packet:
        ...
    elif UDP in packet:
        ...
    return result
```

**Important concepts:**

*No byte order handling needed.* Network protocols are big-endian, so a hand-written parser has to byte-swap every multi-byte field. Scapy has already converted the wire format into Python integers, so `packet[TCP].sport` is directly usable. The one place raw bytes still matter is SNI extraction, which is why that file does its own `int.from_bytes(..., byteorder="big")`.

*The dict is intentionally sparse.* Missing keys are the signal for "this packet has no Layer 3/4 to inspect", which both engines rely on to skip non-IP traffic.

### src/sni_extractor.py

**Purpose:** Extract the domain name from a TLS Client Hello

```python
class SNIExtractor:
    SESSION_ID_OFFSET = 43
    EXTENSION_TYPE_SNI = 0x0000

    def extract(self, payload):
        # 1. Verify TLS record header      (payload[0] == 0x16)
        # 2. Verify Client Hello handshake (payload[5] == 0x01)
        # 3. Skip session ID, cipher suites, compression methods
        # 4. Walk the extension list looking for type 0x0000
        # 5. Return the hostname
```

**The defensive part is the point.** A real capture can be truncated at any byte, and every length field in a TLS record is attacker-controlled. So no declared length is ever trusted:

```python
# Every offset below is validated against this length.
length = len(payload)

if offset + 2 > length:
    return None
...
# Clamp to the real payload size so a truncated capture that
# declares more extension bytes than it carries cannot walk
# off the end.
extensions_end = min(offset + extensions_length, length)
```

Without those checks a hostile or simply cut-off packet raises `IndexError` mid-parse. This is the difference between a parser and a crash.

### src/http_host_extractor.py

**Purpose:** Extract the domain from plaintext HTTP, where there is no SNI

```python
def extract(self, payload):
    if not payload:
        return None

    text = payload.decode("utf-8", errors="ignore")

    for line in text.split("\r\n"):
        if line.lower().startswith("host:"):
            host = line[5:].strip()
            if host:
                return host
    return None
```

`errors="ignore"` matters: binary payloads are fed to this method constantly, and a `UnicodeDecodeError` in the hot path would be a bug, not information.

### src/types.py

**Purpose:** Define the data structures used throughout

**FiveTuple** - frozen so it can be a dict key:

```python
@dataclass(frozen=True)
class FiveTuple:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
```

**Flow** - mutable, because it accumulates state as packets arrive:

```python
@dataclass
class Flow:
    five_tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: Optional[str] = None
    blocked: bool = False
    packet_count: int = 0
```

**AppType** - a string-valued enum, so a CLI argument converts directly:

```python
class AppType(Enum):
    UNKNOWN = "UNKNOWN"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    YOUTUBE = "YOUTUBE"
    FACEBOOK = "FACEBOOK"
    # ... 19 values total
```

```python
# In main.py: "--block-app facebook" → AppType.FACEBOOK
AppType(name.strip().upper())
```

### src/rule_manager.py

**Purpose:** Own every classification and blocking decision

`domain_rules` maps 16 domains to `AppType` values, and three sets hold the blocking rules. All three are constructor parameters with defaults:

```python
self.blocked_ips = (
    set(blocked_ips)
    if blocked_ips is not None
    else {"10.0.0.50"}
)
```

The `is not None` test is deliberate. An explicitly empty list means "block nothing", while omitting the argument means "use the defaults" - two different intentions that a plain `or` would collapse into one.

### src/connection_tracker.py

**Purpose:** Own the flow table and the flow-level verdict

```python
def get_or_create_flow(self, five_tuple, sni=None) -> Flow: ...
def apply_blocking_rules(self, flow): ...
def create_five_tuple(self, packet_data): ...   # returns None for non-IP
def is_packet_blocked(self, packet_data) -> bool: ...
def get_flow_count(self) -> int: ...
```

`is_packet_blocked` is a second-pass helper: after the whole capture has been analysed, it answers "was this packet's flow ultimately blocked?", which is what lets V1 write a filtered capture using the *final* verdict rather than the verdict at the moment that packet was seen.

### src/analyzer.py

**Purpose:** Turn parsed packets and tracked flows into the report

Roughly 20 counters, covering protocol mix, per-source-IP volume, destination ports and services, HTTP methods / hosts / paths / status codes / user agents, TLS handshake count, SNI domains, and suspicious domains. `analyze()` returns the protocol counter and leaves everything else on the instance for `main.py` to print.

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello!**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)      ← SESSION_ID_OFFSET
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

`SESSION_ID_OFFSET = 43` is not a magic number: it is `5` (record header) `+ 4` (handshake header) `+ 2` (client version) `+ 32` (random) `= 43`.

### Our Extraction Code (Simplified)

```python
def extract(self, payload):
    if not payload:
        return None

    length = len(payload)

    if length < 6:
        return None
    if payload[0] != 0x16:          # not a handshake record
        return None
    if payload[5] != 0x01:          # not a Client Hello
        return None

    offset = self.SESSION_ID_OFFSET

    # Skip Session ID
    if offset >= length:
        return None
    session_id_length = payload[offset]
    offset += 1 + session_id_length

    # Skip Cipher Suites
    if offset + 2 > length:
        return None
    cipher_suite_length = int.from_bytes(payload[offset:offset + 2], byteorder="big")
    offset += 2 + cipher_suite_length

    # Skip Compression Methods
    if offset >= length:
        return None
    compression_method_length = payload[offset]
    offset += 1 + compression_method_length

    # Read Extensions Length
    if offset + 2 > length:
        return None
    extensions_length = int.from_bytes(payload[offset:offset + 2], byteorder="big")
    offset += 2
    extensions_end = min(offset + extensions_length, length)

    # Walk the extension list
    while offset + 4 <= extensions_end:
        extension_type = int.from_bytes(payload[offset:offset + 2], byteorder="big")
        extension_length = int.from_bytes(payload[offset + 2:offset + 4], byteorder="big")

        if extension_type == self.EXTENSION_TYPE_SNI:
            sni_offset = offset + 4

            if sni_offset + 5 > length:
                return None

            server_name_length = int.from_bytes(
                payload[sni_offset + 3:sni_offset + 5], byteorder="big"
            )

            name_start = sni_offset + 5
            name_end = name_start + server_name_length

            if name_end > length:
                return None

            server_name = payload[name_start:name_end].decode(errors="ignore")
            return server_name or None

        offset += 4 + extension_length

    return None
```

The textbook version of this function is about fifteen lines - check two bytes, skip four fields, walk the extension list. This one is longer because every single offset is checked against the real payload length first. Nine early returns, and each one corresponds to a specific way a capture can be truncated.

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `--block-ip 10.0.0.50` | All flows whose source IP matches |
| App | `--block-app FACEBOOK` | All flows classified as that application |
| Domain | `--block-domain evil-site.net` | That domain and its subdomains |

**Defaults when no flag is passed:**

| Rule Type | Default |
|-----------|---------|
| IP | `10.0.0.50` |
| App | `FACEBOOK` |
| Domain | `malicious.com`, `phishing.com`, `evil-site.net`, `fake-login.com` |

**Important semantics:** a CLI rule **replaces** the corresponding default set, it does not add to it. `--block-app YOUTUBE` blocks YouTube and *unblocks* Facebook. This is intentional - the flags describe the complete policy for that rule type, so a run is fully described by its command line.

### Domain Matching

```python
# A rule without a dot ("facebook") is treated as a domain label.
# This blocks "www.facebook.com" but not "notfacebook.com".
if "." not in blocked_domain:
    if blocked_domain in domain.split("."):
        return True
    continue

if domain == blocked_domain or domain.endswith("." + blocked_domain):
    return True
```

Two matching modes, and neither is a substring search:

| Rule | Matches | Does NOT match |
|------|---------|----------------|
| `facebook` | `www.facebook.com`, `m.facebook.com` | `notfacebook.com`, `facebook.evil.com` |
| `evil-site.net` | `evil-site.net`, `cdn.evil-site.net` | `notevil-site.net` |

A naive `blocked_domain in domain` check would match `notfacebook.com` for the rule `facebook`. That is a false positive on real traffic, which is why the matcher works on labels instead.

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is the flow already blocked?    │──Yes──► DROP (decision is sticky)
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?    │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

### Flow-Based Blocking

**Important:** we block at the *flow* level, not the packet level.

```
Connection to Facebook:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (Client Hello)  → SNI: www.facebook.com
                           → App: FACEBOOK (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 3 (Data)          → Flow is BLOCKED → DROP
  Packet 4 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```

**Why this approach?**

- We can't identify the app until we see the Client Hello
- Once identified, we block all future packets of that flow
- The connection will fail or time out on the client

**The consequence, stated honestly:** the SYN that precedes the Client Hello is forwarded, because at that moment nothing about the flow is known. In the test capture this is exactly why one blocked Facebook connection produces one dropped packet rather than three. Any real inline DPI device has the same property - classification cannot happen before the classifying bytes arrive.

`is_packet_blocked` exists to close this gap for offline captures: V1 makes a second pass and filters using each flow's *final* verdict.

---

## 10. Building and Running

### Prerequisites

- **Python 3.10+** (the codebase uses `X | None` annotations and builtin generics)
- **Scapy** - the only dependency
- Works on Windows, macOS and Linux
- No compilation step, no admin rights needed (reading a `.pcap` file requires no privileges)

### Setup

```bash
pip install -r requirements.txt
```

### Creating Test Data

```bash
python generate_test_pcap.py
# Generated 77 packets -> input/test_dpi.pcap
# TLS flows with SNI : 16
# HTTP requests      : 2
```

The generator builds a byte-correct minimal TLS Client Hello per domain, so the capture actually exercises `SNIExtractor` rather than a mock. Contents: 16 TLS flows (SYN + Client Hello + server reply), 2 plaintext HTTP GETs with `Host:` and `User-Agent:` headers, 21 payload packets with no SNI (they stay `UNKNOWN` on purpose), and 4 DNS/UDP packets. Total 73 TCP + 4 UDP.

### Running

**Basic usage:**

```bash
python main.py
```

Defaults: reads `input/test_dpi.pcap`, writes `output/v1_filtered_output.pcap` and `output/v2_filtered_output.pcap`, 4 worker threads, built-in blocking rules.

**Custom input and output:**

```bash
python main.py --input input/test_dpi.pcap \
               --v1-output output/v1_filtered_output.pcap \
               --output output/v2_filtered_output.pcap
```

**With blocking (flags are repeatable):**

```bash
python main.py --block-app FACEBOOK \
               --block-app YOUTUBE \
               --block-ip 192.168.1.50 \
               --block-domain evil-site.net
```

**Configure worker threads:**

```bash
python main.py --workers 8
# V2 creates 8 queues, 8 worker threads and 8 independent flow tables
```

### All CLI Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--input` | `input/test_dpi.pcap` | Capture to analyse |
| `--output` | `output/v2_filtered_output.pcap` | V2 filtered capture |
| `--v1-output` | `output/v1_filtered_output.pcap` | V1 filtered capture |
| `--workers` | `4` | Number of V2 worker threads |
| `--block-ip` | `10.0.0.50` | Block a source IP (repeatable) |
| `--block-domain` | 4 suspicious domains | Block a domain (repeatable) |
| `--block-app` | `FACEBOOK` | Block an application (repeatable) |

### Running the Tests

There are 30 test modules under `tests/`, covering both engines - the parser, SNI extraction, domain matching, blocking rules, the flow table, and every V2 piece from the queue up to the full pipeline.

```bash
python -m pytest tests/ -q
```

Some of the earlier modules are script-style rather than assertion-style: they print a trace instead of asserting, which is how they were written while the feature was being built. They are still useful to run individually, because the printed trace is often more informative than a pass/fail:

```bash
python -m tests.test_dpi_decision
python -m tests.test_v2_pipeline
```

Converting the print-based modules to assertions is a known and worthwhile cleanup.

---

## 11. Understanding the Output

### Sample Output

Every number below is the real output of `python main.py` on the bundled `input/test_dpi.pcap`, with the default rules. Long lists are trimmed with `...`.

```
Python DPI Engine
Successfully parsed 77 packets.

Application / Flow Statistics
-----------------------------------
www.google.com            -> GOOGLE     -> FORWARD
www.youtube.com           -> YOUTUBE    -> FORWARD
www.facebook.com          -> FACEBOOK   -> DROP
www.instagram.com         -> INSTAGRAM  -> FORWARD
twitter.com               -> TWITTER    -> FORWARD
github.com                -> GITHUB     -> FORWARD
...

Protocol Statistics:
TCP: 73 (94.8%)
UDP: 4 (5.2%)
ICMP: 0 (0.0%)

Unique Source IPs:
18

Destination Port Statistics:
Port 443: 53 packets
Port 80: 4 packets
Port 53: 4 packets
...

Service Statistics:
HTTPS: 53 packets
HTTP: 4 packets
DNS: 4 packets

Top Service:
HTTPS

HTTP Packet Statistics:
HTTP Packets: 2
HTTPS Packets: 53
TLS Handshakes: 16

HTTP Method Statistics:
GET: 2

HTTP Hosts:
example.com
httpbin.org

HTTP User Agents:
DPI-Test/1.0

========== SECURITY REPORT ==========
Total SNI Domains : 16
Suspicious Domains Found : 0

Detected Suspicious Domains : None Found
Risk Level : LOW

First Parsed Packet:
{'packet_length': 54, 'src_ip': '192.168.1.100', 'dst_ip': '142.250.185.206',
 'protocol': 'TCP', 'src_port': 54552, 'dst_port': 443, 'payload': b''}

Security report saved as security_report.json
V1 filtered PCAP saved as output/v1_filtered_output.pcap


==========================================
       V2 MULTI-THREADED DPI ENGINE
==========================================

V2 DPI REPORT
==========================================
Total Processed : 77
Forwarded       : 76
Dropped         : 1
Skipped Non-IP  : 0
Total Flows     : 43
Worker Errors   : 0

Application Statistics
------------------------------------------
UNKNOWN        : 29
GOOGLE         : 3
YOUTUBE        : 3
FACEBOOK       : 3
INSTAGRAM      : 3
...

Worker Statistics
------------------------------------------
Worker 0        : 7 packets
Worker 1        : 37 packets
Worker 2        : 18 packets
Worker 3        : 15 packets

Output
------------------------------------------
Filtered PCAP   : output/v2_filtered_output.pcap

==========================================
       V2 PIPELINE COMPLETED
==========================================
```

### Sanity-checking the numbers

These are worth being able to explain, because an interviewer will ask:

- `73 + 4 = 77`, and `Total Processed` is also 77, so `Skipped Non-IP` is 0 - every packet in this capture has an IP layer
- `Forwarded 76 + Dropped 1 = 77`, so no packet was silently lost
- `HTTPS Packets: 53` counts packets with destination port 443. `TLS Handshakes: 16` counts payloads starting with `0x16`. Only 16 of those 53 packets are actually handshakes; the rest are data
- `HTTP Packets: 2` counts request payloads starting with a method (`GET`/`POST`/`PUT`/`DELETE`). `Port 80: 4 packets` is higher because it also counts the two SYNs
- `Total SNI Domains: 16` equals the number of TLS conversations, since one Client Hello carries one SNI
- `18` unique source IPs = 1 HTTPS client + 1 HTTP/DNS client + 16 replying servers

### What Each Section Means

| Section | Meaning |
|---------|---------|
| Application / Flow Statistics | Every SNI found, its classification, and the verdict |
| Protocol Statistics | L4 protocol mix, with percentages |
| Unique Source IPs | Distinct senders in the capture |
| Destination Port / Service Statistics | Which services were contacted |
| HTTP Packet Statistics | HTTP vs HTTPS split, and TLS handshakes seen |
| HTTP Hosts / Paths / User Agents | L7 data recovered from plaintext HTTP |
| Security Report | SNI count, suspicious-domain hits, overall risk level |
| First Parsed Packet | The raw parsed dict, for sanity-checking the parser |
| Total Processed | Packets that reached a worker |
| Forwarded / Dropped | Verdict split; forwarded packets are written to the output PCAP |
| Skipped Non-IP | Packets with no IP layer, so no five-tuple to balance on |
| Total Flows | Sum of every worker's private flow table |
| Worker Errors | Packets that raised inside a worker; should always be 0 |
| Worker Statistics | Work distribution across threads |

### Reading the Worker Statistics honestly

The distribution is uneven - 7 / 37 / 18 / 15 rather than roughly 19 each - and that is expected rather than a bug. Work is assigned per *flow*, not per packet, so a flow carrying more packets makes its worker busier. Perfectly even packet counts would actually mean flow affinity was broken.

`Total Flows: 43` is larger than the 18 conversations a human would count, because a five-tuple is direction-dependent: a client→server flow and its server→client reply are two separate entries in the flow table. Flow *balancing* is direction-independent (`canonical()` sorts the endpoints), but flow *tracking* is not. That asymmetry is deliberate - the balancer needs both directions on one worker, while the tracker benefits from telling request traffic apart from response traffic - and it is a good thing to be able to defend.

### Verifying the filtered output

```bash
python -c "from scapy.all import rdpcap; print(len(rdpcap('input/test_dpi.pcap')), len(rdpcap('output/v2_filtered_output.pcap')))"
# 77 76
```

The blocked packet is the Facebook Client Hello. Both captures open in Wireshark, so the filtering can be inspected packet by packet.

---

## 12. Extending the Project

### Ideas for Improvement

1. **Parse Layer 2 and TCP flags**

   ```python
   # In packet_parser.py
   if Ether in packet:
       result["src_mac"] = packet[Ether].src
       result["ether_type"] = packet[Ether].type
   if IP in packet:
       result["ttl"] = packet[IP].ttl
   if TCP in packet:
       result["tcp_flags"] = str(packet[TCP].flags)
   ```

   This unlocks SYN-flood detection and OS fingerprinting from TTL.

2. **Get real parallelism with processes**

   ```python
   # The architecture already supports this: flow affinity means
   # per-worker state is never shared, so workers can be processes.
   from multiprocessing import Process, Queue
   ```

   This is the single highest-value change, because it turns the concurrency story into a measured speedup.

3. **Stream instead of loading the whole capture**

   ```python
   from scapy.all import sniff

   def read_packets(self):
       return sniff(offline=self.file_path, store=False, prn=self.on_packet)
   ```

   Removes the memory ceiling and is the prerequisite for live capture.

4. **Live capture from a network interface**

   ```python
   sniff(iface="eth0", store=False, prn=pipeline.submit_packet)
   ```

   The bounded `ThreadSafeQueue(maxsize=...)` plus a drop counter is already the right backpressure primitive.

5. **Add QUIC / HTTP3 support**

   - QUIC runs over UDP on port 443
   - The SNI lives in the Initial packet, but it is header-protected, so it needs key derivation rather than a plain byte walk
   - Increasingly relevant: a growing share of real HTTPS traffic never sends a TLS Client Hello over TCP at all

---

## Summary

This DPI engine demonstrates:

1. **Network Protocol Parsing** - understanding packet structure and byte layouts
2. **Deep Packet Inspection** - recovering the destination domain from an encrypted connection
3. **Flow Tracking** - stateful, sticky, flow-level decisions rather than per-packet ones
4. **Concurrent Architecture** - flow-hash affinity, per-worker state, lock-free by construction
5. **Producer-Consumer Pattern** - thread-safe queues, clean shutdown, no deadlock on error
6. **Defensive Parsing** - every offset validated, because packet lengths are untrusted input

The key insight is that even HTTPS traffic leaks the destination domain in the TLS handshake, allowing network operators to identify and control application usage.

The second insight is architectural: the reason per-worker flow tables need no locks is flow-hash affinity, and that same property is what would let the workers become processes. Getting the concurrency structure right matters more than the threading primitive used to express it.

---

## Questions?

The code is commented in the same order this document describes. Start with `src/dpi_engine.py` to follow one packet end to end, then read `src/v2/pipeline.py` to see how the same components are driven concurrently. `generate_test_pcap.py` is the fastest way to see what the engine is actually being fed.

Happy learning! 🚀
