"""Shared pacing must bound concurrent work and remain promptly cancellable."""
import threading,time,unittest
from types import SimpleNamespace
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from atlasac.cpubudget import ScanControl,cpu_target

class CPUBudgetTests(unittest.TestCase):
    def test_explicit_speed_modes_preserve_the_low_cpu_default(self):
        self.assertEqual(cpu_target('low',8),.4)
        self.assertEqual(cpu_target('balanced',8),.8)
        self.assertAlmostEqual(cpu_target('fast',8),1.2)
        self.assertEqual(cpu_target('low',64),.6)
        self.assertEqual(cpu_target('fast',64),2.)
        with self.assertRaises(ValueError):cpu_target('invalid')
    def test_pacing_makes_progress_when_timer_wakeups_are_expensive(self):
        # A slow VM can spend more CPU waking two readers every 50 ms than
        # their entire allowance. Waiting only for zero credit then loops
        # without letting either reader do useful work.
        clock=SimpleNamespace(wall=0.,cpu=0.)
        waits=[]
        class CostlyWait:
            def is_set(self):return False
            def wait(self,delay):
                waits.append(delay)
                if len(waits)>20:raise AssertionError('Pacing consumed every CPU credit without making progress')
                clock.wall+=delay;clock.cpu+=.006
                return False
        timers=SimpleNamespace(monotonic=lambda:clock.wall,process_time=lambda:clock.cpu)
        with patch('atlasac.cpubudget.time',timers):
            control=ScanControl(CostlyWait(),cores=.1)
            clock.wall+=.03;clock.cpu+=.03
            self.assertFalse(control.is_set())
        self.assertLess(len(waits),4)

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
