"""自动登录恢复流程的离线回归测试，不访问校园网络或真实凭据。"""

from __future__ import annotations

import fcntl
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import glnc_autologin as glnc


class RecoveryTests(unittest.TestCase):
    def test_auto_mode_checks_all_interfaces_and_reauthenticates_captive_wifi(self):
        """有线可联网也应继续检查仍被 Portal 拦截的无线网卡。"""
        portal = {
            "portal_host": "192.0.2.1",
            "user_ip": "198.51.100.20",
            "user_mac": "a" * 48,
            "user_mac_kind": "portal-token",
            "ac_ip": "192.0.2.2",
            "ac_name": "TEST-AC",
        }
        profile = {
            "login_method": "1",
            "js_version": "4.1.3",
            "portal_port": "801",
            "en_md5": "0",
            "password_cut": "0",
        }
        with (
            patch.object(sys, "argv", ["glnc_autologin.py"]),
            patch.object(glnc, "read_config", return_value={
                "GLNC_ACCOUNT": "test@cmcc",
                "GLNC_PASSWORD": "test-only",
                "GLNC_VERIFY_DELAY": "0",
            }),
            patch.object(glnc, "candidate_interfaces", return_value=["wired0", "wifi0"]),
            patch.object(glnc, "discover_on_interface", side_effect=[
                ("198.51.100.10", "02:00:00:00:00:01", True, {}),
                ("198.51.100.20", "02:00:00:00:00:02", False, portal),
            ]) as discover,
            patch.object(glnc, "fetch_portal_profile", return_value=profile) as fetch,
            patch.object(glnc, "login", return_value=(True, "Portal协议认证成功！")) as login,
            patch.object(glnc, "discover_portal", return_value=(True, {})) as verify,
        ):
            self.assertEqual(glnc.main(), 0)
            self.assertEqual(discover.call_count, 2)
            self.assertEqual(fetch.call_args.args[1], "wifi0")
            self.assertEqual(login.call_args.args[1], "wifi0")
            self.assertEqual(verify.call_args.args[1], "wifi0")

    def test_healthy_interfaces_do_not_send_credentials(self):
        """定时巡检遇到正常 Internet 时，只探测不登录。"""
        with (
            patch.object(sys, "argv", ["glnc_autologin.py"]),
            patch.object(glnc, "read_config", return_value={}),
            patch.object(glnc, "candidate_interfaces", return_value=["wired0"]),
            patch.object(glnc, "discover_on_interface",
                         return_value=("198.51.100.10", "02:00:00:00:00:01", True, {})),
            patch.object(glnc, "fetch_portal_profile") as fetch,
            patch.object(glnc, "login") as login,
        ):
            self.assertEqual(glnc.main(), 0)
            fetch.assert_not_called()
            login.assert_not_called()

    def test_another_running_check_prevents_duplicate_login(self):
        """NM 事件与 timer 同时触发时，共享文件锁拒绝重复执行。"""
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            lock_path = state_dir / "client.lock"
            with lock_path.open("a+") as held:
                fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                with (
                    patch.object(glnc.os, "geteuid", return_value=0),
                    patch.object(glnc, "main") as main,
                ):
                    self.assertEqual(glnc.run_serialized(state_dir), 0)
                    main.assert_not_called()


if __name__ == "__main__":
    unittest.main()
