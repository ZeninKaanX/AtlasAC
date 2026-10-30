"""One cooperative process CPU budget shared by all scan readers.

is_set() also yields when over budget, so existing cancellation checkpoints in
hashing, archive recursion, traversal and collectors share the same allowance.
This is a rolling target, not an OS-enforced instantaneous CPU ceiling.
"""
import os,threading,time

class ScanControl:
    def __init__(self,cancel,cores=None):
        self.cancel=cancel
        self.cores=min(.6,max(.05,(os.cpu_count() or 1)*.05)) if cores is None else max(.01,float(cores))
        self.burst=.02;self.balance=self.burst
        self.wall=time.monotonic();self.cpu=time.process_time();self.lock=threading.Lock();self.next_check=0
    def is_set(self):
        if self.cancel.is_set():return True
        if time.monotonic()<self.next_check:return False
        while not self.cancel.is_set():
            with self.lock:
                wall=time.monotonic();cpu=time.process_time()
                self.balance=min(self.burst,self.balance+(wall-self.wall)*self.cores)-(cpu-self.cpu)
                self.wall=wall;self.cpu=cpu
                # Refill a work burst rather than waking at zero credit.
                # On slow VMs, repeated 50 ms timer wakeups can themselves
                # consume the low CPU allowance and starve both readers.
                delay=(self.burst-self.balance)/self.cores if self.balance<0 else 0
                if delay<=0:self.next_check=wall+.002
            if delay<=0:return False
            # Event.wait wakes immediately on cancellation; polling is needless.
            if self.cancel.wait(delay):return True
        return True
