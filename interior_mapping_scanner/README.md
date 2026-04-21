# Interior Mapping Scanner v2.0

**Advanced System Introspection & Anomaly Detection**

Interior Mapping Scanner v2.0 functions as a real-time host introspection and anomaly detection fabric that maps the internal state of a Linux system into a unified, navigable graph for security analysis, operational visibility, and forensic review. It ingests canonical telemetry from the `/proc` filesystem—covering processes, memory regions, sockets, file descriptors, namespaces, capabilities, and environment signals—and normalizes those signals into a structured model that supports visualization, search, filtering, and live monitoring. Rather than behaving as a passive dashboard, the scanner performs layered analysis to surface security-relevant conditions such as deleted executables, dangerous capabilities, writable-and-executable memory regions, excessive file descriptor usage, and sensitive environment exposure. Its architecture is built around read-only collection, anomaly scoring, and interactive exploration, allowing operators to inspect system behavior without mutating the target environment. With auto-refresh, delta tracking, and detailed metrics, Interior Mapping Scanner v2.0 provides a deterministic, local-first observability layer for system analysis, incident response, and host-level security research.

## Constituent Subsystems

- Advanced Process Analysis
- Capability Analysis Engine
- Memory Region Mapper
- Enhanced Network Monitor
- File Descriptor Inspector
- Namespace Relationship Mapper
- Anomaly Detection Engine
- Real-Time Monitoring Loop
- Search & Focus Navigation Layer
- Metrics Dashboard
- Visualization Graph Renderer
- JSON Export Pipeline

## Comprehensive Capabilities

- Canonical ingestion of `/proc` process, memory, network, file, namespace, and environment data into a unified graph model
- Advanced process introspection with PID, PPID, name, command line, executable path, working directory, UID/GID, state, thread count, and process age
- Capability parsing across all 38 Linux capabilities with dangerous capability identification
- Detection of deleted executables and “ghost process” conditions where a process continues running from a removed binary
- Virtual memory area enumeration for heap, stack, anonymous, file-backed, vdso/vvar, and executable mappings
- Identification of writable-and-executable memory regions as potential code injection or memory corruption risk indicators
- Enhanced network socket discovery with protocol, address, port, state, inode, and owning process mapping
- File descriptor enumeration with FD type classification, target path resolution, and per-process FD statistics
- Namespace mapping across mount, UTS, IPC, PID, network, user, and cgroup boundaries
- Shared namespace detection and process-to-namespace relationship tracking
- Sensitive environment variable scanning for passwords, tokens, and other high-risk secrets
- Container environment detection for Docker, LXC, and Kubernetes-style runtime isolation
- Permission-aware scanning that gracefully handles restricted `/proc` visibility without breaking the overall scan
- Continuous auto-refresh monitoring with configurable intervals and live anomaly re-evaluation
- Delta change tracking to highlight new, removed, or altered system entities between scan cycles
- Real-time search across PID, process name, path, and arbitrary node attributes
- Click-to-focus graph navigation for rapid pivoting between related processes, sockets, files, and namespaces
- Severity-based anomaly classification with high, medium, and low risk groupings
- System-wide metrics aggregation including process states, connection states, memory consumers, FD consumers, and scan performance
- Interactive 3D graph visualization with node-type filtering, connection thresholds, and detailed info panels
- Read-only system inspection that avoids external connectivity and preserves host integrity
- JSON export with versioned graph data, metrics, timestamps, and anomaly records for archival or downstream analysis
- Support for root-level execution to maximize visibility into protected processes and kernel-exposed metadata
- Designed for forensic replay, security triage, and host behavior investigation through a repeatable local scan model

## Security Coverage

- Deleted executable detection
- Dangerous capability detection
- Writable + executable memory detection
- Excessive file descriptor detection
- Sensitive environment variable detection
- Container boundary awareness
- Namespace boundary mapping
- Permission-aware restricted data handling
- Read-only local inspection

## Data Collected

### Process Intelligence

**Basic Attributes:**
- PID, PPID, name, command line
- Executable path, working directory
- Process state, UID, GID
- Thread count
- Process age (uptime)

**Memory:**
- Virtual memory size (VmSize)
- Resident set size (VmRSS)
- Peak memory usage (VmPeak)
- Memory region breakdown
- Executable regions count
- Heap / stack / anonymous mappings
- Writable + executable regions

**Security:**
- Effective capabilities
- Permitted capabilities
- Inheritable capabilities
- Suspicious capability detection
- Seccomp mode
- Container detection

**Files:**
- File descriptor count
- FD type breakdown (regular, device, pipe, socket)
- Interesting files (logs, databases, sockets)

**Environment:**
- Sensitive environment variable detection
- Count of potentially dangerous env vars

### Network Connections

- Protocol (TCP/UDP)
- Local address:port
- Remote address:port
- Connection state
- Socket inode
- Owning process

### File Descriptors

- FD number
- Path/target
- Type (regular, device, pipe, socket, anon)
- Statistics per process

### Namespaces

- All 7 namespace types:
  - mnt (Mount)
  - uts (Hostname)
  - ipc (Inter-Process Communication)
  - pid (Process ID)
  - net (Network)
  - user (User/UID mapping)
  - cgroup (Control Groups)
- Shared namespace detection
- Process-to-namespace mapping

## Visualization Model

### Node Types

- Processes
- Sockets
- Files
- Namespaces

### Relationship Types

- Parent-child process relationships
- Process-to-socket links
- Process-to-file descriptor links
- Process-to-namespace membership links

### Interactive Controls

- Click nodes to inspect full metadata
- Drag to rotate the graph
- Scroll to zoom in/out
- Right-click + drag to pan
- Search to find and focus nodes

## Real-Time Monitoring

- Auto-refresh capability with configurable intervals
- Live anomaly detection
- Delta change tracking
- Continuous system monitoring
- Automatic anomaly re-detection
- Real-time graph updates

## Metrics Dashboard

- Process state distribution
- Network connection statistics
- Top memory consumers
- Top FD consumers
- Scan performance metrics
- Active anomaly counts by severity

## Security & Privacy

- ✅ **100% Local**: All data stays on your machine
- ✅ **Read-Only**: Scanner only reads from /proc
- ✅ **No Network**: No external connections
- ✅ **Permission-Aware**: Handles permission errors gracefully
- ✅ **Anomaly Detection**: Identifies suspicious behavior
- ✅ **Capability Aware**: Tracks privileged operations

## Performance

- **Scan Time**: 2-10 seconds (typical desktop)
- **Node Count**: 500-2000 nodes (typical system)
- **Memory Usage**: ~50-200MB for visualization
- **Refresh**: Supports continuous monitoring
- **Visualization**: Handles 10,000+ nodes smoothly

## Advanced Usage

### Running the Scanner

```bash
cd backend
python3 scanner_v2.py
```

### Launch Visualization

```bash
cd ../frontend
python3 -m http.server 8000
```

Then open: **http://localhost:8000**

### Running as Root

For complete system visibility:

```bash
sudo python3 backend/scanner_v2.py
```

### Custom Scan Intervals

```python
# In scanner_v2.py
scanner.scan_processes_advanced()
scanner.scan_memory_regions(limit=50)
scanner.scan_network_enhanced()
scanner.scan_file_descriptors()
scanner.scan_namespaces()
```

### Export Data

```json
{
  "version": "2.0",
  "scan_timestamp": "2026-04-20T...",
  "nodes": [...],
  "links": [...],
  "metrics": {...},
  "anomalies": [...]
}
```

### Anomaly Filtering

```javascript
const highSeverity = graphData.anomalies.filter(a => a.severity === 'high');
const mediumSeverity = graphData.anomalies.filter(a => a.severity === 'medium');
```

## Metrics Explained

### Process States

- **R**: Running
- **S**: Sleeping (interruptible)
- **D**: Sleeping (uninterruptible)
- **Z**: Zombie
- **T**: Stopped
- **t**: Tracing stop
- **I**: Idle

### Connection States

- **ESTABLISHED**: Active connection
- **LISTEN**: Listening for connections
- **SYN_SENT/RECV**: Connection being established
- **TIME_WAIT**: Connection recently closed
- **CLOSE_WAIT**: Waiting for local close
- **FIN_WAIT1/2**: Connection terminating

## Troubleshooting

### "Permission denied" Errors

**Solution**: Run with sudo:
```bash
sudo python3 backend/scanner_v2.py
```

### High Memory Usage

**Solution**: Reduce memory region scan limit:
```python
scanner.scan_memory_regions(limit=10)
```

### Slow Scans

**Solution**: Disable memory region scanning for speed:
```python
# scanner.scan_memory_regions()
```

### Graph Performance Issues

**Solution**: Increase minimum connections filter to reduce visible nodes, or filter by type.

## v1.0 vs v2.0 Comparison

| Feature | v1.0 | v2.0 |
|---------|------|------|
| Process Scanning | ✅ Basic | ✅ Advanced + Capabilities |
| Network Analysis | ✅ Basic | ✅ Enhanced + Stats |
| Memory Mapping | ❌ | ✅ VMA Analysis |
| Anomaly Detection | ❌ | ✅ 5 Types |
| Capability Detection | ❌ | ✅ All 38 Caps |
| Real-time Monitoring | ❌ | ✅ Auto-refresh |
| Search | ❌ | ✅ Full-text |
| Metrics Dashboard | ❌ | ✅ Comprehensive |
| Container Detection | ❌ | ✅ Docker/K8s/LXC |
| Security Analysis | ❌ | ✅ Multi-layer |

## Future Roadmap

Planned enhancements:
- [ ] eBPF integration for kernel-level tracing
- [ ] Neo4j backend for massive graphs
- [ ] Historical timeline view
- [ ] Machine learning anomaly detection
- [ ] Export to SIEM systems
- [ ] Differential scanning (show changes)
- [ ] Process ancestry tree view
- [ ] Binary hash verification
- [ ] Yara rule integration
- [ ] Custom alerting rules

## Technical Details

### Architecture

```text
/proc filesystem
    ↓
Scanner (Python)
    ↓
JSON Graph Data
    ↓
3D Visualization (React + 3d-force-graph)
    ↓
Interactive Analysis
```

### Data Model

**Nodes**: Process, Socket, File, Namespace  
**Edges**: PARENT_OF, HAS_SOCKET, HAS_FD, IN_NAMESPACE  
**Attributes**: 50+ per node type  
**Metrics**: System-wide statistics  
**Anomalies**: Security event list

### Technologies

- **Backend**: Python 3 (stdlib only)
- **Frontend**: React 18 + 3d-force-graph
- **Rendering**: WebGL (Three.js)
- **Layout**: Force-directed (d3-force-3d)
- **Data**: JSON graph format

## License

Educational and research use.

## Contributing

Contributions welcome! Areas of interest:
- New anomaly detection rules
- Additional data sources
- Performance optimizations
- Export format support
- Documentation improvements

---

**Built for security research, system analysis, and forensics** 🔍
