"""Shared pacing must bound concurrent work and remain promptly cancellable."""
import threading,time,unittest
from concurrent.futures import ThreadPoolExecutor
from atlasac.cpubudget import ScanControl

class CPUBudgetTests(unittest.TestCase):
    def test_readers_share_budget_and_cancel_interrupts_wait(self):
        cancel=threading.Event();control=ScanControl(cancel,cores=.15)
        started=time.monotonic();cpu=time.process_time();counts=[]
        def work():
            count=0
            while not control.is_set():
                for n in range(1500):count+=n%7
            return count
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures=[pool.submit(work) for _ in range(3)]
            time.sleep(.55);cancel_at=time.monotonic();cancel.set()
            counts=[f.result(timeout=1) for f in futures]
        self.assertLess(time.monotonic()-cancel_at,.3)
        self.assertGreater(sum(counts),0)
        # Includes the bounded burst and test orchestration, not an exact CPU cap.
        self.assertLess((time.process_time()-cpu)/(time.monotonic()-started),.5)
