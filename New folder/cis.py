"""Write one CSV from structured, read-only RHEL 9 CIS validation results."""

from __future__ import annotations

import csv
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from ansible.plugins.callback import CallbackBase


DOCUMENTATION = r"""
callback: rhel9_cis_csv_v2
type: aggregate
short_description: Write structured RHEL 9 CIS validation results to CSV
version_added: "2.0"
requirements:
  - Enable with callbacks_enabled=rhel9_cis_csv_v2
"""


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "rhel9_cis_csv_v2"
    CALLBACK_NEEDS_ENABLED = True

    def __init__(self):
        super().__init__()
        self.payloads: list[dict] = []
        self.remediation_events: dict[tuple[str, str], list[dict]] = {}
        self.remediation_hosts: set[str] = set()
        self.active_controls: dict[str, str] = {}


    @staticmethod
    def _backup_records(action, item, args):
        """Record actual backup results; never infer that a missing backup exists."""
        if not item.get('changed'):
            return []
        records = []
        supplied = item.get('file_backups') or []
        if action == 'command' and isinstance(item.get('stdout'), str):
            try:
                payload = json.loads(item['stdout'])
            except (ValueError, TypeError):
                payload = {}
            if isinstance(payload, dict) and payload.get('cis_changed_file_backups') is True:
                supplied = payload.get('file_backups') or []
        for entry in supplied:
            if not isinstance(entry, dict):
                continue
            original = entry.get('original_file')
            changed = entry.get('changed_file') or original
            backup = entry.get('backup_file')
            if not all(isinstance(p, str) and p.startswith('/') for p in (original, changed)):
                continue
            if backup is not None and not (isinstance(backup, str) and backup.startswith('/')):
                continue
            records.append(dict(original_file=original, changed_file=changed,
                                backup_file=backup,
                                change_type=entry.get('change_type', 'modified'),
                                original_aliases=entry.get('original_aliases', []),
                                control_ids=entry.get('control_ids', [])))
        if records:
            return records
        # Explicit same-folder copies are pre-change backups, not target edits.
        source = args.get('src')
        destination = item.get('dest') or args.get('dest')
        if (action == 'copy' and args.get('remote_src') is True
                and isinstance(source, str) and source.startswith('/')
                and isinstance(destination, str) and destination.startswith('/')
                and os.path.dirname(source) == os.path.dirname(destination)
                and os.path.basename(destination).startswith('backup_CIS_remediation_')
                and destination.endswith('.bak')):
            loop_item = item.get('item') or {}
            return [dict(original_file=source, changed_file=source, backup_file=destination,
                         original_aliases=loop_item.get('aliases', []) if isinstance(loop_item, dict) else [],
                         change_type='prechange_backup')]
        original = args.get('dest') or args.get('path') or item.get('dest') or item.get('path')
        if action == 'cron' and not original:
            cron_file = args.get('cron_file')
            if cron_file:
                original = str(cron_file) if str(cron_file).startswith('/') else '/etc/cron.d/' + str(cron_file)
            else:
                original = '/var/spool/cron/' + str(args.get('user') or 'root')
        backup = item.get('backup_file') or item.get('backup')
        changed = item.get('dest') or item.get('path') or original
        if isinstance(backup, str) and backup.startswith('/'):
            return [dict(original_file=original or 'Not returned by module',
                         changed_file=changed or 'Not returned by module',
                         backup_file=backup, change_type='modified')]
        if (action in {'copy', 'template', 'lineinfile', 'blockinfile', 'replace', 'file', 'cron'}
                and isinstance(original, str) and original.startswith('/')
                and item.get('state') != 'directory'):
            # A content/permission change without a returned backup is NOT proof
            # that this was a newly-created file. Make the gap visible in CSV.
            return [dict(original_file=original, changed_file=changed or original,
                         backup_file=None, change_type='backup_not_reported')]
        return []

    @staticmethod
    def _format_backup_details(events):
        lines = []
        verified = set()
        for event in events:
            records = event.get('backup_details') or []
            if isinstance(records, dict): records = [records]
            for record in records:
                if record.get('backup_file'):
                    verified.update([record.get('original_file'), record.get('changed_file')])
                    verified.update(record.get('original_aliases', []))
        for event in events:
            records = event.get('backup_details') or []
            if isinstance(records, dict):
                records = [records]
            for record in records:
                original = record.get('original_file', 'Not returned by module')
                if record.get('change_type') == 'backup_not_reported' and original in verified:
                    continue
                changed = record.get('changed_file') or original
                backup = record.get('backup_file')
                if not backup:
                    backup = ('N/A - file did not exist before remediation'
                              if record.get('change_type') == 'created'
                              else 'NOT_REPORTED - no verified pre-change backup returned')
                lines.append(f'Original: {original} | Changed: {changed} | Backup: {backup}')
        return '\n'.join(dict.fromkeys(lines))

    @staticmethod
    def _brief(value, limit=1200):
        """Keep CSV cells readable without copying commands or embedded programs."""
        text = ' '.join(str(value or '').split())
        return text if len(text) <= limit else text[:limit] + ' [truncated]'

    @classmethod
    def _format_remediation_output(cls, events):
        lines = []
        for event in events:
            # Final backup records have their own column. Internal preparation is
            # not remediation, even when a helper reports changed=true.
            if event.get('internal_backup'):
                continue
            failed = event.get('status') == 'failed'
            if not failed and not event.get('changed'):
                continue
            status = 'FAILED' if failed else 'CHANGED'
            task = cls._brief(event.get('task', 'Remediation task'), 300)
            module = cls._brief(event.get('module', ''), 80)
            line = f'{status}: {task} [{module}]'
            path = event.get('dest') or event.get('path')
            if path:
                line += ' | ' + cls._brief(path, 300)
            if event.get('output') == 'REDACTED: Ansible no_log task':
                line += ' | Details redacted'
            if failed:
                if event.get('rc') is not None:
                    line += ' | rc=' + str(event['rc'])
                # stdout/cmd/parameters can contain entire scripts or secrets.
                line += ' | ' + cls._brief(event.get('msg') or event.get('backup_error')
                                          or 'See Ansible task failure output')
            lines.append(line)
        return '\n'.join(dict.fromkeys(lines))

    def _record_remediation(self, result, failed=False):
        """Collect real task results between the pre and remediation payloads.

        Control IDs come from the task/block names, rule tags or conditions.
        Shared tasks can be associated with several selected controls. No
        target commands are executed by this callback.
        """
        host = result._host.get_name()
        if host not in self.remediation_hosts:
            return
        task = getattr(result, '_task', None)
        if task is None:
            return
        data = result._result or {}
        if data.get('skipped'):
            return
        action = str(getattr(task, 'action', '')).rsplit('.', 1)[-1]
        task_tags = getattr(task, 'tags', []) or []
        finalized_backup = 'cis_changed_file_backups' in task_tags
        internal_backup = finalized_backup or 'cis_backup_prepare' in task_tags
        if not failed and 'cis_backup_prepare' in task_tags:
            return
        if not failed and action in  {
            'assert', 'debug', 'fail', 'find', 'getent', 'include_role',
            'include_tasks', 'include_vars', 'import_role', 'import_tasks',
            'meta', 'read_csv', 'service_facts', 'set_fact', 'setup', 'slurp',
            'stat', 'wait_for', 'wait_for_connection',
        }:
            return

        ids = set()
        node = task
        visited = set()
        hidden = bool(data.get('_ansible_no_log'))
        while node is not None and id(node) not in visited:
            visited.add(id(node))
            hidden = hidden or bool(getattr(node, 'no_log', False))
            name = str(getattr(node, 'name', '') or '')
            # Prefer the nearest explicit control name over a broad parent.
            if not ids:
                ids.update(re.findall(r'(?<![\d.])([1-7](?:\.\d+)+)(?![\d.])', name))
            if not ids:
                conditions = str(getattr(node, 'when', []) or [])
                ids.update(re.findall(r"['\"]([1-7](?:\.\d+)+)['\"]", conditions))
                rule_text = str(getattr(node, 'tags', []) or []) + ' ' + conditions
                ids.update(
                    value.replace('_', '.')
                    for value in re.findall(r'rhel9cis_rule_([1-7](?:_\d+)+)', rule_text)
                )
            node = getattr(node, '_parent', None)
        control = self.active_controls.get(host)
        if control:
            # The per-control wrapper is authoritative, including collection
            # helper tasks with generic names or names listing several rules.
            ids = {control}
        prechange_copy = 'cis_prechange_backup' in (getattr(task, 'tags', []) or [])
        if not ids and prechange_copy:
            for value in data.get('results', [data]):
                loop_item = value.get('item') or {}
                if isinstance(loop_item, dict):
                    ids.update(str(c) for c in loop_item.get('control_ids', []))
        if not ids and finalized_backup:
            try:
                backup_payload = json.loads(data.get('stdout') or '{}')
            except (ValueError, TypeError):
                backup_payload = {}
            if isinstance(backup_payload, dict) and backup_payload.get('cis_changed_file_backups') is True:
                ids.update(str(c) for c in backup_payload.get('control_ids', []))
            for record in self._backup_records(action, data, {}):
                ids.update(str(c) for c in record.get('control_ids', []))
        if not ids:
            return

        def event_for(item):
            private = hidden or bool(item.get('_ansible_no_log'))
            event = {
                'task': str(getattr(task, 'name', '') or action),
                'module': action,
                'status': 'failed' if item.get('failed', failed if item is data else False) else 'ok',
                'changed': bool(item.get('changed', False)),
                'controls': sorted(ids),
                'internal_backup': internal_backup,
            }
            if private:
                event['output'] = 'REDACTED: Ansible no_log task'
                return event
            # Select result fields; never dump invocation, environment, facts,
            # slurped file contents or module-specific service status dictionaries.
            for key in ('cmd', 'rc', 'stdout', 'stderr', 'msg', 'path', 'dest',
                        'state', 'mode', 'owner', 'group', 'uid', 'gid',
                        'enabled', 'masked', 'failures', 'command_results',
                        'recovery_snapshot_dir'):
                if key in item and not (finalized_backup and key in {'cmd', 'stdout'}):
                    event[key] = item[key]
            if finalized_backup:
                try:
                    payload = json.loads(item.get('stdout') or '{}')
                except (ValueError, TypeError):
                    payload = {}
                if isinstance(payload, dict) and payload.get('error'):
                    event['backup_error'] = payload['error']
                    event['recovery_snapshot_dirs'] = payload.get('recovery_snapshot_dirs', [])
            args = (item.get('invocation') or {}).get('module_args') or {}
            records = self._backup_records(action, item, args)
            if records:
                event['backup_details'] = records
            safe_keys = ('name', 'path', 'dest', 'src', 'state', 'mode', 'owner',
                         'group', 'enabled', 'masked', 'regexp', 'line', 'section',
                         'option', 'value', 'argv', 'cmd', 'recurse', 'commands',
                         'paths', 'backup_root')
            event['parameters'] = {} if finalized_backup else {key: args[key] for key in safe_keys if key in args}
            # File permission diffs are useful even when module stdout is empty.
            # Omit content diffs, which could contain credentials.
            diffs = item.get('diff') or []
            if isinstance(diffs, dict):
                diffs = [diffs]
            changes = []
            for diff in diffs:
                if not isinstance(diff, dict):
                    continue
                change = {}
                for side in ('before', 'after'):
                    values = diff.get(side)
                    if isinstance(values, dict):
                        change[side] = {key: values[key] for key in
                                        ('path', 'mode', 'owner', 'group', 'state')
                                        if key in values}
                if any(change.values()):
                    changes.append(change)
            if changes:
                event['changes'] = changes
            return event

        items = data.get('results')
        if not isinstance(items, list) or not any(isinstance(item, dict) for item in items):
            items = [data]
        for item in items:
            if not isinstance(item, dict) or item.get('skipped'):
                continue
            event = event_for(item)
            item_ids = ids
            if prechange_copy and isinstance(item.get('item'), dict):
                item_ids = set(str(c) for c in item['item'].get('control_ids', [])) or ids
                event['controls'] = sorted(item_ids)
            for control_id in item_ids:
                scoped = dict(event)
                if finalized_backup:
                    scoped['controls'] = [control_id]
                    scoped['backup_details'] = [record for record in event.get('backup_details', [])
                        if not record.get('control_ids') or control_id in record['control_ids']]
                    if not scoped['backup_details'] and scoped['status'] != 'failed':
                        continue
                self.remediation_events.setdefault((host, control_id), []).append(scoped)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._record_remediation(result, failed=True)

    def v2_runner_on_unreachable(self, result):
        self._record_remediation(result, failed=True)

    def v2_runner_on_ok(self, result, **kwargs):
        facts = (result._result or {}).get('ansible_facts') or {}
        if "cis_active_remediation_control_id" in facts:
            host = result._host.get_name()
            control = str(facts["cis_active_remediation_control_id"] or "")
            if control:
                self.active_controls[host] = control
            else:
                self.active_controls.pop(host, None)
        self._record_remediation(result)
        data = result._result or {}
        message = data.get("msg")
        if not isinstance(message, dict):
            return
        payload = message.get("cis_report_payload")
        if not isinstance(payload, dict):
            return
        payload = dict(payload)
        payload["host"] = str(payload.get("host") or result._host.get_name())
        host = payload['host']
        if payload.get('stage') == 'pre':
            self.active_controls.pop(host, None)
            self.remediation_events = {
                key: value for key, value in self.remediation_events.items()
                if key[0] != host
            }
            if payload.get('operation') == 'remediate':
                self.remediation_hosts.add(host)
        elif payload.get('stage') in {'remediation', 'final'}:
            self.remediation_hosts.discard(host)
        self.payloads.append(payload)

    def v2_playbook_on_stats(self, stats):
        if not self.payloads:
            return

        output = Path(
            os.environ.get("RHEL9_CIS_CSV_OUTPUT", "reports/rhel9_cis_results.csv")
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        generated = datetime.now(timezone.utc).isoformat()
        rows = []
        controls: dict[tuple[str, str], dict] = {}

        for payload in self.payloads:
            host = str(payload.get("host", "unknown"))
            pre_results = payload.get("results") or []
            post_by_id = {
                item.get("control_id"): item
                for item in (payload.get("post_results") or [])
            }
            attempted = set(payload.get("remediation_attempted") or [])
            skipped_by_policy = {
                    str(item)
                    for item in (payload.get("remediation_skipped_by_policy") or [])
                }
            stage_priority = {
                "pre": 1,
                "remediation": 2,
                "final": 3,
            }.get(payload.get("stage"), 0)

            for pre in pre_results:
                key = (host, str(pre.get("control_id", "")))
                if key not in controls or stage_priority >= controls[key]["priority"]:
                    controls[key] = {
                        "host": host,
                        "operation": payload.get("operation", "validate"),
                        "pre": pre,
                        "post": post_by_id.get(pre.get("control_id")),
                        "attempted": attempted,
                        "skipped_by_policy": skipped_by_policy,
                        "errors": [error for error in (payload.get('remediation_errors') or [])
                                   if str(error.get('control_id')) == key[1]],
                        "priority": stage_priority,
                    }

        for state in controls.values():
            host = state["host"]
            operation = state["operation"]
            pre = state["pre"]
            post = state["post"]
            attempted = state["attempted"]
            control_id = str(pre.get("control_id", ""))
            pre_status = str(pre.get("status", "VALIDATION_ERROR"))
            post_status = str(post.get("status")) if post else "NOT_RUN"

            events = self.remediation_events.get((host, control_id), [])

            event_errors = [
                {
                    "control_id": control_id,
                    "task": event.get("task", "Unknown task"),
                    "message": event.get(
                        "msg",
                        event.get("output", "Remediation task failed"),
                    ),
                    "rc": event.get("rc", "not returned"),
                }
                for event in events
                if event.get("status") == "failed"
            ]

            state["errors"] = list(state.get("errors") or []) + event_errors

            backup_details = self._format_backup_details(events)
            remediation_summary = self._format_remediation_output(events)

            if operation == "validate":
                final_status = pre_status
            elif pre_status != "NON_COMPLIANT":
                final_status = pre_status
            elif (
                control_id in state["skipped_by_policy"]
                and control_id not in attempted
            ):
                final_status = "REMEDIATION_SKIPPED_BY_POLICY"
            elif control_id not in attempted:
                final_status = "REMEDIATION_NOT_ATTEMPTED"
            elif state['errors']:
                final_status = "REMEDIATION_INCOMPLETE"
            elif post_status == "COMPLIANT":
                final_status = "REMEDIATION_COMPLETED"
            elif post_status == "NON_COMPLIANT":
                final_status = "NON_COMPLIANT_AFTER_REMEDIATION"
            elif post_status == "VALIDATION_ERROR":
                final_status = "POST_VALIDATION_ERROR"
            elif post_status == "NOT_RUN":
                final_status = "REMEDIATION_INCOMPLETE"
            else:
                final_status = post_status

            rows.append(
                {
                    "generated_utc": generated,
                    "host": host,
                    "plugin_id": pre.get("plugin_id", ""),
                    "phase": str(pre.get("phase", "")).zfill(2),
                    "control_id": control_id,
                    "checkpoint": pre.get("checkpoint", ""),
                    "validation_type": pre.get("validation_type", ""),
                    "validation_source": pre.get("validation_source", ""),
                    "remediation_safe": (
                        "YES" if pre.get("remediation_safe") else "NO"
                    ),
                    "pre_validation": pre_status,
                    "remediation_required": (
                        "YES" if pre_status == "NON_COMPLIANT" else "NO"
                    ),
                    "remediation_attempted": (
                        "YES" if control_id in attempted else "NO"
                    ),
                    "remediation_completed": (
                        "YES" if final_status == "REMEDIATION_COMPLETED" else "NO"
                    ),
                    "post_validation": post_status,
                    "final_status": final_status,
                    "pre_validation_output": pre.get("evidence", ""),
                    "remediation_output": (
                        remediation_summary
                        if remediation_summary
                        else (
                            "Not run: remediation explicitly skipped by "
                            "cis_remediation_skip_ids."
                            if final_status == "REMEDIATION_SKIPPED_BY_POLICY"
                            else (
                                "No changed remediation task result was captured; "
                                "do not infer a change from the final status."
                                if control_id in attempted
                                else (
                                    "Not run: validation only, already compliant, "
                                    "missing input, unsupported control or skipped by policy."
                                )
                            )
                        )
                    ),
                    "backup_details": backup_details,
                    "remediation_error": '\n'.join(dict.fromkeys(
                        self._brief(error.get('task', 'Remediation')) + ': '
                        + self._brief(error.get('message', 'Task failed'))
                        + (' | rc=' + str(error['rc']) if error.get('rc') is not None else '')
                        for error in state['errors'])),
                    "evidence": (
                        post.get("evidence", "") if post else pre.get("evidence", "")
                    ),
                }
            )

        fields = [
            "generated_utc",
            "host",
            "plugin_id",
            "phase",
            "control_id",
            "checkpoint",
            "validation_type",
            "validation_source",
            "remediation_safe",
            "pre_validation",
            "remediation_required",
            "remediation_attempted",
            "remediation_completed",
            "post_validation",
            "final_status",
            "pre_validation_output",
            "remediation_output",
            "backup_details",
            "remediation_error",
            "evidence",
        ]

        def control_key(row):
            return (
                row["host"],
                [int(part) for part in row["control_id"].split(".")],
            )

        with output.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(sorted(rows, key=control_key))

        self._display.display(f"RHEL 9 CIS CSV report: {output}", color="green") 
