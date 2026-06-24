import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ProcessNode:
    pid: int
    ppid: int
    name: str
    create_time: str
    session_id: str
    threads: int
    handles: int
    children: list = field(default_factory=list)
    depth: int = 0
    suspicious: bool = False
    suspicion_reason: str = ""


class ProcessTreeBuilder:

    def __init__(self):
        self._nodes: dict[int, ProcessNode] = {}
        self._roots: list[ProcessNode] = []

    def build(self, processes: list) -> list:
        self._nodes.clear()
        self._roots.clear()

        for p in processes:
            pid = int(p.get("PID", p.get("pid", 0)))
            ppid = int(p.get("PPID", p.get("ppid", 0)))
            name = p.get("ImageFileName", p.get("name", "unknown"))

            node = ProcessNode(
                pid=pid, ppid=ppid, name=name,
                create_time=p.get("CreateTime", p.get("create_time", "")),
                session_id=str(p.get("SessionId", p.get("session_id", ""))),
                threads=int(p.get("Threads", p.get("threads", 0))),
                handles=int(p.get("Handles", p.get("handles", 0))),
            )
            self._nodes[pid] = node

        for pid, node in self._nodes.items():
            parent = self._nodes.get(node.ppid)
            if parent and parent.pid != pid:
                parent.children.append(node)
            else:
                self._roots.append(node)

        self._calculate_depths(self._roots, 0)
        self._flag_suspicious()
        logger.info("Built process tree: %d nodes, %d roots", len(self._nodes), len(self._roots))
        return self._roots

    def _calculate_depths(self, nodes: list, depth: int):
        for node in nodes:
            node.depth = depth
            self._calculate_depths(node.children, depth + 1)

    def _flag_suspicious(self):
        orphan_system_procs = {"svchost.exe", "csrss.exe", "lsass.exe"}
        for node in self._nodes.values():
            if node.name.lower() in orphan_system_procs and node.ppid not in self._nodes:
                if node.ppid != 0:
                    node.suspicious = True
                    node.suspicion_reason = f"Orphaned system process (PPID {node.ppid} not found)"

            if node.depth > 8:
                node.suspicious = True
                node.suspicion_reason = f"Deeply nested process (depth={node.depth})"

            if node.name.lower() == "cmd.exe" or node.name.lower() == "powershell.exe":
                for child in node.children:
                    if child.name.lower() in ("cmd.exe", "powershell.exe"):
                        child.suspicious = True
                        child.suspicion_reason = "Shell spawned from another shell"

    def render_text(self, nodes: list = None, indent: int = 0) -> str:
        if nodes is None:
            nodes = self._roots
        lines = []
        for node in sorted(nodes, key=lambda n: n.pid):
            prefix = "  " * indent
            flag = " [!]" if node.suspicious else ""
            reason = f" ({node.suspicion_reason})" if node.suspicion_reason else ""
            lines.append(
                f"{prefix}├─ {node.name} (PID:{node.pid} PPID:{node.ppid} "
                f"Session:{node.session_id} Threads:{node.threads}){flag}{reason}"
            )
            if node.children:
                lines.append(self.render_text(node.children, indent + 1))
        return "\n".join(lines)

    def render_json(self, nodes: list = None) -> list:
        if nodes is None:
            nodes = self._roots
        result = []
        for node in sorted(nodes, key=lambda n: n.pid):
            entry = {
                "pid": node.pid,
                "ppid": node.ppid,
                "name": node.name,
                "create_time": node.create_time,
                "session_id": node.session_id,
                "threads": node.threads,
                "handles": node.handles,
                "depth": node.depth,
                "suspicious": node.suspicious,
                "suspicion_reason": node.suspicion_reason,
                "children": self.render_json(node.children),
            }
            result.append(entry)
        return result

    def find_process(self, pid: int) -> Optional[ProcessNode]:
        return self._nodes.get(pid)

    def get_ancestry(self, pid: int) -> list:
        chain = []
        node = self._nodes.get(pid)
        visited = set()
        while node and node.pid not in visited:
            chain.append(node)
            visited.add(node.pid)
            node = self._nodes.get(node.ppid)
        chain.reverse()
        return chain

    def get_suspicious_chains(self) -> list:
        chains = []
        for node in self._nodes.values():
            if node.suspicious:
                chains.append(self.get_ancestry(node.pid))
        return chains

    def get_statistics(self) -> dict:
        total = len(self._nodes)
        suspicious = sum(1 for n in self._nodes.values() if n.suspicious)
        max_depth = max((n.depth for n in self._nodes.values()), default=0)
        orphans = sum(
            1 for n in self._nodes.values()
            if n.ppid not in self._nodes and n.ppid != 0
        )
        return {
            "total_processes": total,
            "suspicious_processes": suspicious,
            "max_depth": max_depth,
            "orphaned_processes": orphans,
            "root_processes": len(self._roots),
        }
