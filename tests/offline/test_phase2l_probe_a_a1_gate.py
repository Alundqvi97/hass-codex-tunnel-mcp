"""A1 fail-stop review regressions: mock-only, no fork, privilege or host I/O.

Mocking os._exit with BaseException is ONLY to observe that the trusted
bootstrap chooses irrevocable OS termination. A mock is not OS enforcement.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))

from probe_a_runner import ForkGuardianLauncher, OneShotRunner, RunnerDenied
from test_phase2l_probe_a_runtime import P, FakeKernel, FakeReader, MockWork, MockResources


class HardStopped(BaseException):
    pass


class Endpoint:
    def __init__(self):
        self.closed=False
    def close(self):
        self.closed=True


class MockProcess:
    def __init__(self, *, state, failure=None):
        self.state=state
        self.failure=failure
    def start(self):
        self.state["spawn_attempted"]+=1
        if self.failure=="start":
            raise RuntimeError("simulated partially started child")


class MockContext:
    def __init__(self, state, *, failure=None):
        self.state=state
        self.failure=failure
    def Process(self, **kwargs):
        self.state["construct_attempted"]+=1
        if self.failure=="construction":
            raise RuntimeError("simulated Process constructor failure")
        return MockProcess(state=self.state,failure=self.failure)


class FailstopTests(unittest.TestCase):
    def make(self, failure=None):
        state={"endpoints":[],"spawn_attempted":0,"construct_attempted":0,
               "audit":[],"backend":0}
        def backend(plan):
            state["backend"]+=1
            if failure=="backend":
                raise RuntimeError("simulated failed root backend")
            class Resources(MockResources):
                def preflight(self):
                    if failure=="resources":
                        return False
                    return super().preflight()
            return FakeReader(FakeKernel(0)),MockWork(),Resources()
        def post_observer(plan):
            if failure=="post_factory":
                raise RuntimeError("simulated post-observer failure")
            return lambda *args:None
        def context(mode):
            if failure=="context":
                raise RuntimeError("simulated context failure")
            return MockContext(state, failure=failure)
        def pair(*,clock):
            if failure=="socket":
                raise OSError("simulated socketpair allocation failure")
            if failure=="partial_pair":
                one=Endpoint()
                state["endpoints"].append(one)
                return (one,)
            left,right=Endpoint(),Endpoint()
            state["endpoints"] += [left,right]
            return left,right
        def drop():
            if failure=="drop":
                raise PermissionError("simulated CAP_SETPCAP/UID failure")
            if failure=="drop_false":
                return False
            return True
        launcher=ForkGuardianLauncher(
            backend_factory=backend, post_observer_factory=post_observer,
            controller_drop=drop,root_check=lambda:0,
            context_factory=context,transport_pair_factory=pair,
            clock=lambda:1)
        return launcher,state

    def assert_fails_root(self,launcher, *, stage=76,plan=P):
        with patch("probe_a_runner.os.geteuid",return_value=0), \
             patch("probe_a_runner.os._exit",side_effect=HardStopped) as hard_exit:
            with self.assertRaises(HardStopped):
                launcher.launch(plan,200,140)
        hard_exit.assert_called_once_with(stage)

    def test_invalid_privileged_constructor_does_not_raise_to_caller(self):
        for kwargs in (
            {"backend_factory":None},
            {"backend_factory":lambda p:None,"controller_drop":None},
            {"backend_factory":lambda p:None,"transport_pair_factory":None},
        ):
            with self.subTest(kwargs=sorted(kwargs)):
                with patch("probe_a_runner.os.geteuid",return_value=0), \
                     patch("probe_a_runner.os._exit",side_effect=HardStopped) as hard_exit:
                    with self.assertRaises(HardStopped):
                        ForkGuardianLauncher(**kwargs)
                hard_exit.assert_called_once_with(76)

    def test_invalid_launch_plan_and_expired_work_window_hard_stop(self):
        launch,state=self.make()
        self.assert_fails_root(launch,plan="unreviewed")
        self.assertEqual(state["backend"],0)
        self.assertEqual(state["spawn_attempted"],0)
        self.assertEqual(state["endpoints"],[])

    def test_backend_construction_failure_before_child(self):
        launch,state=self.make("backend")
        self.assert_fails_root(launch)
        self.assertEqual(state["backend"],1)
        self.assertEqual(state["spawn_attempted"],0)
        self.assertEqual(state["endpoints"],[])

    def test_failed_resource_preflight_has_no_cleanup_or_audit_claim(self):
        launch,state=self.make("resources")
        launch.verify_after=lambda *a:state["audit"].append(a)
        self.assert_fails_root(launch)
        self.assertEqual(state["construct_attempted"],0)
        self.assertEqual(state["audit"],[])
        self.assertEqual(state["endpoints"],[])

    def test_kernel_observer_construction_failure_before_fork(self):
        launch,state=self.make()
        with patch("probe_a_observer.KernelReadback",
                   side_effect=RuntimeError("simulated observer constructor failure")):
            self.assert_fails_root(launch)
        self.assertEqual(state["construct_attempted"],0)
        self.assertEqual(state["endpoints"],[])

    def test_kernel_preflight_readback_failure_before_fork(self):
        launch,state=self.make()
        with patch("probe_a_observer.KernelReadback.preflight",
                   side_effect=PermissionError("simulated readback failure")):
            self.assert_fails_root(launch)
        self.assertEqual(state["construct_attempted"],0)

    def test_post_observer_factory_failure_before_fork(self):
        launch,state=self.make("post_factory")
        self.assert_fails_root(launch)
        self.assertEqual(state["endpoints"],[])

    def test_context_creation_failure_before_socket(self):
        launch,state=self.make("context")
        self.assert_fails_root(launch)
        self.assertEqual(state["endpoints"],[])

    def test_socket_factory_failure_has_no_spurious_cleanup_claim(self):
        launch,state=self.make("socket")
        self.assert_fails_root(launch)
        self.assertEqual(state["spawn_attempted"],0)
        self.assertEqual(state["endpoints"],[])

    def test_partial_socket_pair_is_closed_before_hard_exit(self):
        launch,state=self.make("partial_pair")
        self.assert_fails_root(launch)
        self.assertEqual(len(state["endpoints"]),1)
        self.assertTrue(state["endpoints"][0].closed)
        self.assertEqual(state["spawn_attempted"],0)

    def test_process_constructor_failure_closes_both_endpoints(self):
        launch,state=self.make("construction")
        self.assert_fails_root(launch)
        self.assertEqual(state["construct_attempted"],1)
        self.assertEqual(state["spawn_attempted"],0)
        self.assertTrue(all(x.closed for x in state["endpoints"]))

    def test_uncertain_process_start_failure_closes_endpoints_and_exits_77(self):
        launch,state=self.make("start")
        self.assert_fails_root(launch,stage=77)
        self.assertEqual(state["spawn_attempted"],1)
        self.assertTrue(all(x.closed for x in state["endpoints"]))

    def test_partial_capability_failure_after_start_never_returns(self):
        for failure in ("drop","drop_false"):
            launch,state=self.make(failure)
            with self.subTest(failure=failure):
                self.assert_fails_root(launch,stage=77)
                self.assertEqual(state["spawn_attempted"],1)
                self.assertTrue(all(x.closed for x in state["endpoints"]))

    def test_lied_privilege_drop_after_start_never_returns(self):
        launch,state=self.make()
        with patch("probe_a_runner.verify_unprivileged",return_value=False):
            self.assert_fails_root(launch,stage=77)
        self.assertEqual(state["spawn_attempted"],1)
        self.assertTrue(all(x.closed for x in state["endpoints"]))

    def test_intercepted_baseexception_is_not_converted_to_success(self):
        launch,state=self.make()
        with patch("probe_a_runner.verify_unprivileged",
                   side_effect=KeyboardInterrupt("simulated signal")):
            self.assert_fails_root(launch,stage=77)
        self.assertTrue(all(x.closed for x in state["endpoints"]))

    def test_no_audit_claim_if_untrusted_caller_tried_interception(self):
        launch,state=self.make("drop")
        launch.verify_after=lambda *a:state["audit"].append(a)
        with patch("probe_a_runner.os.geteuid",return_value=0), \
             patch("probe_a_runner.os._exit",side_effect=HardStopped):
            with self.assertRaises(HardStopped):
                try:
                    launch.launch(P,200,140)
                except Exception:
                    self.fail("caught a normal error in privileged caller")
        self.assertEqual(state["audit"],[])
        self.assertTrue(all(x.closed for x in state["endpoints"]))


class RunnerEarlyReturnTests(unittest.TestCase):
    def assert_runner_root_stop(self,runner,*, activated=False,approval=None):
        with patch("probe_a_runner.os.geteuid",return_value=0), \
             patch("probe_a_runner.verify_unprivileged",return_value=False), \
             patch("probe_a_runner.os._exit",side_effect=HardStopped) as hard_exit:
            with self.assertRaises(HardStopped):
                runner.run(activated=activated,approval=approval)
        self.assertGreaterEqual(hard_exit.call_count,1)
        self.assertTrue(all(args.args==(77,) for args in hard_exit.call_args_list))

    def test_disabled_early_return_cannot_return_to_root(self):
        self.assert_runner_root_stop(OneShotRunner(P))

    def test_replay_refusal_cannot_return_to_root(self):
        runner=OneShotRunner(P)
        runner.used=True
        self.assert_runner_root_stop(runner,activated=True,approval="fake")

    def test_invalid_plan_refusal_cannot_return_to_root(self):
        self.assert_runner_root_stop(OneShotRunner("not-a-plan"),
                                     activated=True,approval="fake")

    def test_verifier_refusal_and_callback_exception_cannot_return_to_root(self):
        for verifier in (lambda *a:False,
                         lambda *a:(_ for _ in ()).throw(SystemExit(0))):
            with self.subTest(verifier=verifier):
                self.assert_runner_root_stop(
                    OneShotRunner(P,launcher=object(),verify_activation=verifier),
                    activated=True,approval="fake")

    def test_failed_launcher_does_not_audit_under_root(self):
        audits=[]
        class Launcher:
            def launch(self,*a):
                raise RuntimeError("simulated pre-drop failure")
            def verify_after(self,*a):
                audits.append(a)
        self.assert_runner_root_stop(
            OneShotRunner(P,launcher=Launcher(),
                          verify_activation=lambda *a:True),
            activated=True,approval="fake")
        self.assertEqual(audits,[])

    def test_false_launcher_success_cannot_enter_root_controller(self):
        audits=[]
        class Launcher:
            def launch(self,*a):
                return object()
            def verify_after(self,*a):
                audits.append(a)
        with patch("probe_a_runner.control",
                   side_effect=AssertionError("controller must not run")) as ctrl:
            self.assert_runner_root_stop(
                OneShotRunner(P,launcher=Launcher(),
                              verify_activation=lambda *a:True),
                activated=True,approval="fake")
            ctrl.assert_not_called()
        self.assertEqual(audits,[])

    def test_nonroot_denial_retains_original_behavior(self):
        with patch("probe_a_runner.os.geteuid",return_value=65534):
            runner=OneShotRunner(P)
            self.assertEqual(runner.run(),"BLOCKED_DISABLED_OR_UNAPPROVED")
            self.assertEqual(runner.run(activated=True),"BLOCKED_REPLAY")


if __name__=="__main__":
    unittest.main()
