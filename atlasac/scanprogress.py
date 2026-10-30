"""Candidate-file progress; no whole-disk percentage before discovery finishes."""
from collections import deque


class ScanProgress:
    def __init__(self):self.samples=deque(maxlen=128);self.discovery_complete=False
    def update(self,completed,total,discovery_complete,now):
        if discovery_complete and not self.discovery_complete:
            self.samples.clear();self.discovery_complete=True
        if completed and (not self.samples or completed!=self.samples[-1][1] and now-self.samples[-1][0]>=.2):
            self.samples.append((now,completed))
        while len(self.samples)>1 and now-self.samples[0][0]>30:self.samples.popleft()
        percent=None;eta=None
        if discovery_complete:
            percent=100. if not total else min(100.,100.*completed/total)
            if completed>=total:eta=0.
            elif len(self.samples)>=2:
                elapsed=now-self.samples[0][0];done=completed-self.samples[0][1]
                if elapsed>=2 and done>=5 and now-self.samples[-1][0]<10:
                    eta=(total-completed)*elapsed/done
        return {'processed_candidates':completed,'total_candidates':total if discovery_complete else None,
                'progress_percent':round(percent,1) if percent is not None else None,
                'eta_seconds':round(eta) if eta is not None else None}
