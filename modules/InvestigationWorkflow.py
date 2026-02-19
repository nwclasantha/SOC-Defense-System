"""
Investigation Workflow Engine
Manages security incident investigation workflows
Tracks tasks, evidence, and investigation progress
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import json
import hashlib

class WorkflowStatus(Enum):
    """Workflow status"""
    CREATED = "created"
    IN_PROGRESS = "in_progress"
    WAITING = "waiting"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ESCALATED = "escalated"

class TaskStatus(Enum):
    """Task status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

class TaskPriority(Enum):
    """Task priority"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class InvestigationTask:
    """Investigation task"""
    task_id: str
    workflow_id: str
    title: str
    description: str
    status: TaskStatus
    priority: TaskPriority
    assigned_to: str
    created_at: datetime
    due_at: datetime
    completed_at: Optional[datetime] = None
    depends_on: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    playbook_step: Optional[str] = None

@dataclass
class Evidence:
    """Investigation evidence"""
    evidence_id: str
    workflow_id: str
    evidence_type: str  # log, file, screenshot, network_capture, etc.
    description: str
    source: str
    collected_at: datetime
    collected_by: str
    data: Any
    chain_of_custody: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

@dataclass
class InvestigationWorkflow:
    """Investigation workflow"""
    workflow_id: str
    incident_id: str
    title: str
    description: str
    status: WorkflowStatus
    priority: TaskPriority
    created_at: datetime
    created_by: str
    assigned_team: str
    tasks: List[InvestigationTask]
    evidence: List[Evidence]
    timeline: List[Dict[str, Any]]
    findings: List[str]
    affected_systems: List[str]
    iocs: List[str]  # Indicators of Compromise
    estimated_impact: str
    playbook_name: Optional[str] = None

class InvestigationWorkflowEngine:
    """
    Manages investigation workflows for security incidents
    Provides playbook automation and task management
    """

    def __init__(self):
        self.workflows: Dict[str, InvestigationWorkflow] = {}
        self.playbooks: Dict[str, List[Dict[str, Any]]] = {}
        self.task_templates: Dict[str, Dict[str, Any]] = {}

        # Initialize default playbooks
        self._init_default_playbooks()

    def create_workflow(self,
                       incident_id: str,
                       title: str,
                       description: str,
                       priority: TaskPriority,
                       assigned_team: str,
                       playbook_name: Optional[str] = None) -> InvestigationWorkflow:
        """
        Create new investigation workflow

        Args:
            incident_id: Related incident ID
            title: Workflow title
            description: Workflow description
            priority: Priority level
            assigned_team: Team assigned to investigation
            playbook_name: Optional playbook to use

        Returns:
            Created workflow
        """
        workflow_id = hashlib.sha256(
            f"{incident_id}{datetime.utcnow()}".encode()
        ).hexdigest()[:16]

        workflow = InvestigationWorkflow(
            workflow_id=workflow_id,
            incident_id=incident_id,
            title=title,
            description=description,
            status=WorkflowStatus.CREATED,
            priority=priority,
            created_at=datetime.utcnow(),
            created_by="system",
            assigned_team=assigned_team,
            tasks=[],
            evidence=[],
            timeline=[{
                "timestamp": datetime.utcnow().isoformat(),
                "action": "workflow_created",
                "details": {"title": title}
            }],
            findings=[],
            affected_systems=[],
            iocs=[],
            estimated_impact="unknown",
            playbook_name=playbook_name
        )

        # Generate tasks from playbook
        if playbook_name and playbook_name in self.playbooks:
            self._generate_tasks_from_playbook(workflow, playbook_name)

        self.workflows[workflow_id] = workflow

        return workflow

    def add_task(self,
                workflow_id: str,
                title: str,
                description: str,
                priority: TaskPriority,
                assigned_to: str,
                depends_on: List[str] = None) -> InvestigationTask:
        """
        Add task to workflow

        Args:
            workflow_id: Workflow ID
            title: Task title
            description: Task description
            priority: Task priority
            assigned_to: Assignee
            depends_on: List of task IDs this depends on

        Returns:
            Created task
        """
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            raise ValueError("Workflow not found")

        task_id = hashlib.sha256(
            f"{workflow_id}{title}{datetime.utcnow()}".encode()
        ).hexdigest()[:12]

        task = InvestigationTask(
            task_id=task_id,
            workflow_id=workflow_id,
            title=title,
            description=description,
            status=TaskStatus.PENDING,
            priority=priority,
            assigned_to=assigned_to,
            created_at=datetime.utcnow(),
            due_at=datetime.utcnow() + self._get_due_timedelta(priority),
            depends_on=depends_on or []
        )

        workflow.tasks.append(task)
        workflow.timeline.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": "task_added",
            "details": {"task_id": task_id, "title": title}
        })

        return task

    def update_task_status(self,
                          workflow_id: str,
                          task_id: str,
                          status: TaskStatus,
                          notes: str = None) -> bool:
        """
        Update task status

        Args:
            workflow_id: Workflow ID
            task_id: Task ID
            status: New status
            notes: Optional notes

        Returns:
            Success status
        """
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return False

        task = self._find_task(workflow, task_id)
        if not task:
            return False

        old_status = task.status
        task.status = status

        if status == TaskStatus.COMPLETED:
            task.completed_at = datetime.utcnow()

        if notes:
            task.notes.append(f"[{datetime.utcnow().isoformat()}] {notes}")

        workflow.timeline.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": "task_status_updated",
            "details": {
                "task_id": task_id,
                "old_status": old_status.value,
                "new_status": status.value
            }
        })

        # Check if workflow should advance
        self._check_workflow_progress(workflow)

        return True

    def add_evidence(self,
                    workflow_id: str,
                    evidence_type: str,
                    description: str,
                    source: str,
                    collected_by: str,
                    data: Any,
                    tags: List[str] = None) -> Evidence:
        """
        Add evidence to investigation

        Args:
            workflow_id: Workflow ID
            evidence_type: Type of evidence
            description: Evidence description
            source: Source of evidence
            collected_by: Who collected it
            data: Evidence data
            tags: Optional tags

        Returns:
            Created evidence
        """
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            raise ValueError("Workflow not found")

        evidence_id = hashlib.sha256(
            f"{workflow_id}{evidence_type}{datetime.utcnow()}".encode()
        ).hexdigest()[:12]

        evidence = Evidence(
            evidence_id=evidence_id,
            workflow_id=workflow_id,
            evidence_type=evidence_type,
            description=description,
            source=source,
            collected_at=datetime.utcnow(),
            collected_by=collected_by,
            data=data,
            chain_of_custody=[{
                "timestamp": datetime.utcnow().isoformat(),
                "action": "collected",
                "actor": collected_by
            }],
            tags=tags or []
        )

        workflow.evidence.append(evidence)
        workflow.timeline.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": "evidence_added",
            "details": {
                "evidence_id": evidence_id,
                "type": evidence_type,
                "description": description
            }
        })

        return evidence

    def add_finding(self, workflow_id: str, finding: str):
        """Add investigation finding"""
        workflow = self.workflows.get(workflow_id)
        if workflow:
            workflow.findings.append({
                "timestamp": datetime.utcnow().isoformat(),
                "finding": finding
            })

    def add_ioc(self, workflow_id: str, ioc: str, ioc_type: str):
        """Add Indicator of Compromise"""
        workflow = self.workflows.get(workflow_id)
        if workflow:
            workflow.iocs.append({
                "value": ioc,
                "type": ioc_type,
                "discovered_at": datetime.utcnow().isoformat()
            })

    def get_pending_tasks(self, workflow_id: str, assigned_to: str = None) -> List[InvestigationTask]:
        """
        Get pending tasks for workflow

        Args:
            workflow_id: Workflow ID
            assigned_to: Filter by assignee

        Returns:
            List of pending tasks
        """
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return []

        pending_tasks = []

        for task in workflow.tasks:
            if task.status != TaskStatus.PENDING:
                continue

            # Check if dependencies are met
            if task.depends_on:
                deps_met = all(
                    self._find_task(workflow, dep_id).status == TaskStatus.COMPLETED
                    for dep_id in task.depends_on
                    if self._find_task(workflow, dep_id)
                )
                if not deps_met:
                    continue

            if assigned_to and task.assigned_to != assigned_to:
                continue

            pending_tasks.append(task)

        return pending_tasks

    def escalate_workflow(self, workflow_id: str, reason: str):
        """Escalate workflow to higher tier"""
        workflow = self.workflows.get(workflow_id)
        if workflow:
            workflow.status = WorkflowStatus.ESCALATED
            workflow.timeline.append({
                "timestamp": datetime.utcnow().isoformat(),
                "action": "workflow_escalated",
                "details": {"reason": reason}
            })

    def complete_workflow(self, workflow_id: str, summary: str):
        """Complete investigation workflow"""
        workflow = self.workflows.get(workflow_id)
        if workflow:
            workflow.status = WorkflowStatus.COMPLETED
            workflow.timeline.append({
                "timestamp": datetime.utcnow().isoformat(),
                "action": "workflow_completed",
                "details": {"summary": summary}
            })

    def generate_investigation_report(self, workflow_id: str) -> Dict[str, Any]:
        """
        Generate investigation report

        Args:
            workflow_id: Workflow ID

        Returns:
            Investigation report
        """
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return {"error": "Workflow not found"}

        # Calculate metrics
        total_tasks = len(workflow.tasks)
        completed_tasks = len([t for t in workflow.tasks if t.status == TaskStatus.COMPLETED])
        progress = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0

        duration = (datetime.utcnow() - workflow.created_at).total_seconds() / 3600  # hours

        return {
            "workflow_id": workflow_id,
            "incident_id": workflow.incident_id,
            "title": workflow.title,
            "status": workflow.status.value,
            "priority": workflow.priority.value,
            "created_at": workflow.created_at.isoformat(),
            "duration_hours": duration,
            "progress_percent": progress,
            "tasks": {
                "total": total_tasks,
                "completed": completed_tasks,
                "pending": len([t for t in workflow.tasks if t.status == TaskStatus.PENDING]),
                "in_progress": len([t for t in workflow.tasks if t.status == TaskStatus.IN_PROGRESS])
            },
            "evidence_count": len(workflow.evidence),
            "findings": workflow.findings,
            "iocs": workflow.iocs,
            "affected_systems": workflow.affected_systems,
            "estimated_impact": workflow.estimated_impact,
            "timeline": workflow.timeline[-10:]  # Last 10 events
        }

    def _generate_tasks_from_playbook(self, workflow: InvestigationWorkflow, playbook_name: str):
        """Generate tasks from playbook template"""
        playbook = self.playbooks.get(playbook_name, [])

        for step in playbook:
            task = InvestigationTask(
                task_id=hashlib.sha256(
                    f"{workflow.workflow_id}{step['title']}{datetime.utcnow()}".encode()
                ).hexdigest()[:12],
                workflow_id=workflow.workflow_id,
                title=step["title"],
                description=step["description"],
                status=TaskStatus.PENDING,
                priority=TaskPriority[step.get("priority", "MEDIUM")],
                assigned_to=workflow.assigned_team,
                created_at=datetime.utcnow(),
                due_at=datetime.utcnow() + timedelta(hours=step.get("due_hours", 24)),
                playbook_step=playbook_name
            )

            workflow.tasks.append(task)

    def _init_default_playbooks(self):
        """Initialize default investigation playbooks"""

        # Ransomware investigation playbook
        self.playbooks["ransomware"] = [
            {
                "title": "Isolate affected systems",
                "description": "Disconnect infected systems from network immediately",
                "priority": "CRITICAL",
                "due_hours": 1
            },
            {
                "title": "Identify ransomware variant",
                "description": "Analyze ransom note and file extensions to identify variant",
                "priority": "HIGH",
                "due_hours": 2
            },
            {
                "title": "Determine initial infection vector",
                "description": "Analyze logs to find how ransomware entered the system",
                "priority": "HIGH",
                "due_hours": 4
            },
            {
                "title": "Check backup integrity",
                "description": "Verify backups are clean and restorable",
                "priority": "CRITICAL",
                "due_hours": 2
            },
            {
                "title": "Document affected assets",
                "description": "Create list of all encrypted systems and files",
                "priority": "MEDIUM",
                "due_hours": 8
            },
            {
                "title": "Notify stakeholders",
                "description": "Inform management and affected parties",
                "priority": "HIGH",
                "due_hours": 4
            }
        ]

        # Data breach investigation playbook
        self.playbooks["data_breach"] = [
            {
                "title": "Contain the breach",
                "description": "Stop ongoing data exfiltration",
                "priority": "CRITICAL",
                "due_hours": 1
            },
            {
                "title": "Identify compromised data",
                "description": "Determine what data was accessed or stolen",
                "priority": "CRITICAL",
                "due_hours": 4
            },
            {
                "title": "Assess breach scope",
                "description": "Determine number of affected individuals/records",
                "priority": "HIGH",
                "due_hours": 8
            },
            {
                "title": "Preserve evidence",
                "description": "Collect and preserve all relevant logs and artifacts",
                "priority": "HIGH",
                "due_hours": 6
            },
            {
                "title": "Legal notification assessment",
                "description": "Determine legal notification requirements",
                "priority": "HIGH",
                "due_hours": 12
            }
        ]

        # Malware investigation playbook
        self.playbooks["malware"] = [
            {
                "title": "Isolate infected systems",
                "description": "Quarantine affected systems",
                "priority": "CRITICAL",
                "due_hours": 1
            },
            {
                "title": "Collect malware samples",
                "description": "Extract malware for analysis",
                "priority": "HIGH",
                "due_hours": 2
            },
            {
                "title": "Analyze malware behavior",
                "description": "Conduct static and dynamic analysis",
                "priority": "HIGH",
                "due_hours": 8
            },
            {
                "title": "Identify infection vector",
                "description": "Determine how malware entered environment",
                "priority": "MEDIUM",
                "due_hours": 12
            },
            {
                "title": "Search for additional infections",
                "description": "Hunt for similar infections across network",
                "priority": "HIGH",
                "due_hours": 6
            }
        ]

    def _find_task(self, workflow: InvestigationWorkflow, task_id: str) -> Optional[InvestigationTask]:
        """Find task in workflow"""
        for task in workflow.tasks:
            if task.task_id == task_id:
                return task
        return None

    def _check_workflow_progress(self, workflow: InvestigationWorkflow):
        """Check and update workflow progress"""
        if not workflow.tasks:
            return

        all_completed = all(t.status == TaskStatus.COMPLETED for t in workflow.tasks)

        if all_completed and workflow.status != WorkflowStatus.COMPLETED:
            workflow.status = WorkflowStatus.IN_PROGRESS  # Ready for final review

        pending_tasks = [t for t in workflow.tasks if t.status == TaskStatus.PENDING]
        if not pending_tasks and workflow.status == WorkflowStatus.CREATED:
            workflow.status = WorkflowStatus.IN_PROGRESS

    def _get_due_timedelta(self, priority: TaskPriority) -> timedelta:
        """Get due date based on priority"""
        if priority == TaskPriority.CRITICAL:
            return timedelta(hours=4)
        elif priority == TaskPriority.HIGH:
            return timedelta(hours=24)
        elif priority == TaskPriority.MEDIUM:
            return timedelta(days=3)
        else:
            return timedelta(days=7)

    def get_workflow_metrics(self) -> Dict[str, Any]:
        """Get overall workflow metrics"""
        active_workflows = [w for w in self.workflows.values()
                          if w.status in [WorkflowStatus.CREATED, WorkflowStatus.IN_PROGRESS]]

        return {
            "total_workflows": len(self.workflows),
            "active_workflows": len(active_workflows),
            "completed_workflows": len([w for w in self.workflows.values()
                                       if w.status == WorkflowStatus.COMPLETED]),
            "escalated_workflows": len([w for w in self.workflows.values()
                                       if w.status == WorkflowStatus.ESCALATED]),
            "critical_workflows": len([w for w in active_workflows
                                      if w.priority == TaskPriority.CRITICAL])
        }
