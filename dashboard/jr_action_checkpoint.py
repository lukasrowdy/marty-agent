"""Externally enforced five-action approval controller.

The authenticated dashboard must own open_task/approve/stop. Never expose these
as model tools or interpret page text as approval. Reuse ONE controller across
model replies/toolboxes. Hooks must enforce and verify pause/resume/cutoff
outside the model. A hook returning anything except True fails closed.

This is an action budget, not the independent network watchdog. On process
restart the controller is stopped; no permission or continuation is restored.
"""
from __future__ import annotations

import secrets
import threading

ACTIONS_PER_CHECKPOINT = 5


class CheckpointRequired(Exception):
    pass


class ActionCheckpoint:
    def __init__(self, *, pause, resume, cutoff):
        self._pause = pause
        self._resume = resume
        self._cutoff = cutoff
        self._lock = threading.RLock()
        self._execution = threading.RLock()
        self._generation = 0
        self._owner = None
        self._task = None
        self._phase = 'stopped'
        self._checkpoint = None
        self._report = None
        self._used = 0
        self._remaining = 0
        self._reason = 'Not started'

    def _identity(self, owner, task):
        if not owner or owner != self._owner or task != self._task:
            raise CheckpointRequired('This approval belongs to a different task or user')

    def status(self, owner, task):
        with self._lock:
            self._identity(owner, task)
            return {'phase': self._phase, 'limit': ACTIONS_PER_CHECKPOINT,
                    'used': self._used, 'remaining': self._remaining,
                    'checkpoint': self._checkpoint, 'reason': self._reason,
                    'report': dict(self._report) if self._report else None}

    def _fault(self, reason):
        with self._lock:
            self._generation += 1
            self._phase = 'fault'
            self._remaining = 0
            self._checkpoint = None
            self._reason = reason
        try:
            self._cutoff()
        except Exception:
            pass
        # Remain faulted even if emergency poweroff succeeded. A fault does not
        # become permission to resume, and arbitrary exception text stays local.

    def _park(self, reason):
        with self._lock:
            if self._phase in ('stopped', 'fault'):
                return
            self._generation += 1
            generation = self._generation
            self._phase = 'pausing'
            self._remaining = 0
            self._checkpoint = None
            self._report = None
            self._reason = reason
        try:
            confirmed = self._pause() is True
        except Exception:
            confirmed = False
        with self._lock:
            if self._generation != generation:
                return  # Stop or fault supersedes an in-flight pause.
            if confirmed:
                self._phase = 'awaiting_approval'
                self._checkpoint = secrets.token_hex(16)
                return
        self._fault('Pause could not be verified; emergency cutoff requested')

    def open_task(self, owner, task):
        """Called by authenticated dashboard Start; grants no action permission."""
        if not isinstance(owner, str) or not owner or not isinstance(task, str) or not task:
            raise ValueError('A user and task are required')
        with self._execution:
            with self._lock:
                if self._phase != 'stopped':
                    raise CheckpointRequired('Stop the existing task before opening another')
                self._owner, self._task = owner, task
                self._used = 0
                self._phase = 'opening'
            self._park('Review the initial plan')
            return self.status(owner, task)

    def set_report(self, owner, task, checkpoint, *, completed, uncertain, next_steps, reason):
        """Report text is data. Supplying it never grants permission."""
        report = {'completed': completed, 'uncertain': uncertain,
                  'next_steps': next_steps, 'reason': reason}
        if any(not isinstance(v, str) or not v.strip() or len(v) > 4000 for v in report.values()):
            raise ValueError('Each check-in field needs concise, nonempty text')
        with self._lock:
            self._identity(owner, task)
            if self._phase != 'awaiting_approval' or checkpoint != self._checkpoint:
                raise CheckpointRequired('That checkpoint is no longer current')
            if self._report is not None:
                raise CheckpointRequired('The displayed plan is fixed; request a new checkpoint to revise it')
            self._report = report

    def revise_plan(self, owner, task, checkpoint):
        """Trusted dashboard Change direction invalidates the displayed plan."""
        with self._lock:
            self._identity(owner, task)
            if self._phase != 'awaiting_approval' or checkpoint != self._checkpoint:
                raise CheckpointRequired('That checkpoint is no longer current')
            self._generation += 1
            self._checkpoint = secrets.token_hex(16)
            self._report = None
            self._reason = 'Review the revised direction before continuing'
            return self.status(owner, task)

    def approve(self, owner, task, checkpoint):
        """Trusted dashboard action only. One fresh checkpoint buys five calls."""
        with self._execution:
            with self._lock:
                self._identity(owner, task)
                if self._phase != 'awaiting_approval' or checkpoint != self._checkpoint:
                    raise CheckpointRequired('That checkpoint is no longer current')
                if not self._report:
                    raise CheckpointRequired('Read a complete check-in before continuing')
                generation = self._generation
                self._phase = 'resuming'
                self._checkpoint = None  # Consume approval before opening access.
            try:
                confirmed = self._resume() is True
            except Exception:
                confirmed = False
            with self._lock:
                cancelled = self._generation != generation
                if confirmed and not cancelled:
                    self._used = 0
                    self._remaining = ACTIONS_PER_CHECKPOINT
                    self._phase = 'running'
                    self._reason = 'User approved the next five actions'
                    return self.status(owner, task)
            # A late resume must not undo Stop. Cut off again after it returns.
            self._fault('Resume failed or was cancelled; emergency cutoff requested')
            raise CheckpointRequired('Continuing could not be verified')

    def execute(self, owner, task, action):
        """One tool call, including attempts and retries, is one budget unit."""
        with self._execution:
            with self._lock:
                self._identity(owner, task)
                if self._phase != 'running' or self._remaining <= 0:
                    raise CheckpointRequired('Paused for Lukas: explicit approval is required')
                self._remaining -= 1  # Reserve before executing, never refund.
                self._used += 1
            failed = True
            try:
                result = action()
                failed = False
                return result
            finally:
                with self._lock:
                    must_park = self._phase == 'running' and (failed or self._remaining == 0)
                if must_park:
                    self._park('An action failed; review before continuing' if failed else
                               'Five actions completed; review the next steps')

    def check_in(self, owner, task, reason='Task finished or direction needs review'):
        with self._execution:
            with self._lock:
                self._identity(owner, task)
                if self._phase != 'running':
                    raise CheckpointRequired('No running batch to pause')
            self._park(reason)
            return self.status(owner, task)

    def stop(self, owner, task):
        # Does not wait on an executing action, pause or resume hook.
        with self._lock:
            self._identity(owner, task)
            self._generation += 1
            self._remaining = 0
            self._phase = 'stopped'
            self._checkpoint = None
            self._report = None
            self._reason = 'Stopped by user'
        try:
            confirmed = self._cutoff() is True
        except Exception:
            confirmed = False
        if not confirmed:
            self._fault('Power-off could not be confirmed')
        return self.status(owner, task)
