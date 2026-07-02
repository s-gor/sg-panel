from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EC2 = ROOT / "deploy" / "ec2-first-install.sh"
BOOTSTRAP = ROOT / "install-from-github.sh"
PURGE = ROOT / "deploy" / "purge-test-server.sh"
HTTP = ROOT / "deploy" / "configure-http.sh"
ACCESS = ROOT / "deploy" / "configure-panel-access.sh"
HTTPS = ROOT / "deploy" / "configure-https.sh"
REPAIR = ROOT / "deploy" / "repair-panel-access.sh"
README = ROOT / "README.md"


class InstallRecoveryTest(unittest.TestCase):
    def test_incomplete_install_returns_to_http_wizard(self):
        text = EC2.read_text(encoding="utf-8")
        self.assertIn("Обнаружена незавершённая установка", text)
        self.assertIn("Повторно запускаю мастер", text)
        self.assertIn("Домен и HTTPS для начальной установки не требуются", text)
        self.assertNotIn("configured_https_is_usable", text)

    def test_initial_install_configures_http_without_certbot_issue(self):
        text = EC2.read_text(encoding="utf-8")
        self.assertIn('bash "$TARGET/deploy/configure-http.sh"', text)
        self.assertNotIn("certbot certonly", text)
        self.assertNotIn("check_dns", text)
        self.assertIn("Начальная установка работает по HTTP", text)

    def test_completion_marker_is_written_after_panel_check(self):
        text = EC2.read_text(encoding="utf-8")
        check_pos = text.index('curl -fsS --max-time 5 -H "Host: $host"')
        marker_pos = text.rindex('write_install_marker "$PANEL_MODE" "$PANEL_HOST"')
        self.assertGreater(marker_pos, check_pos)


    def test_new_install_backup_helpers_are_safe_with_set_e(self):
        for path in (HTTP, ACCESS):
            text = path.read_text(encoding="utf-8")
            self.assertIn("backup_path(){", text)
            self.assertIn("return 0", text[text.index("backup_path(){"):text.index("rollback(){")])
            self.assertNotIn('[[ -e "$source" || -L "$source" ]] && cp', text)

    def test_ec2_public_address_uses_imdsv2_before_private_route(self):
        text = EC2.read_text(encoding="utf-8")
        self.assertIn("X-aws-ec2-metadata-token-ttl-seconds", text)
        self.assertIn("latest/meta-data/public-ipv4", text)
        self.assertLess(text.index("detect_ec2_public_ipv4"), text.index("ip -4 route get 1.1.1.1"))

    def test_installer_has_spinner_and_final_panel_url(self):
        text = EC2.read_text(encoding="utf-8")
        self.assertIn("run_stage(){", text)
        self.assertIn("[SG-Panel] [%sOK%s] %s (%s сек)", text)
        self.assertIn("[SG-Panel] [%s%s%s] %s (%s сек)", text)
        self.assertIn(r"local frames='|/-\\'", text)
        self.assertIn("Этап 7/7", text)
        self.assertIn("Панель:", text)
        self.assertIn("$PANEL_URL", text)


    def test_installer_expected_versions_match_package_version(self):
        version_text = (ROOT / "xpanel" / "__init__.py").read_text(encoding="utf-8")
        version = version_text.split('"')[1]
        for path in (EC2, ROOT / "install-or-upgrade.sh"):
            installer_text = path.read_text(encoding="utf-8")
            self.assertIn(f'EXPECTED_VERSION="{version}"', installer_text, path.name)

    def test_reconfigure_is_forwarded_by_bootstrap(self):
        ec2_text = EC2.read_text(encoding="utf-8")
        bootstrap_text = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("--reconfigure", ec2_text)
        self.assertIn('INSTALLER_ARGS=("$@")', bootstrap_text)
        self.assertIn('"${INSTALLER_ARGS[@]}"', bootstrap_text)

    def test_existing_password_and_panel_access_are_preserved(self):
        text = EC2.read_text(encoding="utf-8")
        self.assertIn("Существующий пароль администратора будет сохранён", text)
        self.assertIn("Текущий доступ к панели будет сохранён", text)
        self.assertIn("Сохраняю существующий HTTP/HTTPS-доступ", text)

    def test_http_config_keeps_backend_on_loopback(self):
        text = HTTP.read_text(encoding="utf-8")
        self.assertIn('"XPANEL_BIND_ADDRESS": "127.0.0.1"', text)
        self.assertIn('"XPANEL_SECURE_COOKIES": "0"', text)
        self.assertIn("proxy_pass http://127.0.0.1", text)
        self.assertIn("PANEL_ACCESS_MODE=http", text)

    def test_https_is_a_later_panel_access_operation(self):
        text = ACCESS.read_text(encoding="utf-8")
        self.assertIn('--mode http', text)
        self.assertIn('--mode https', text)
        self.assertIn("certbot certonly", text)
        self.assertIn("PANEL_ACCESS_MODE=https", text)
        self.assertIn("configure-http.sh", text)


    def test_https_can_be_switched_back_to_http_without_new_hsts_policy(self):
        text = HTTPS.read_text(encoding="utf-8")
        self.assertNotIn("Strict-Transport-Security", text)


    def test_https_recovers_old_http_ip_url_and_repairs_stale_state(self):
        https_text = HTTPS.read_text(encoding="utf-8")
        repair_text = REPAIR.read_text(encoding="utf-8")
        upgrade_text = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
        self.assertIn(r"error_page 497 =308 https://$DOMAIN:$HTTPS_PORT\$request_uri;", https_text)
        self.assertIn("repair-panel-access.sh", https_text)
        self.assertIn("PANEL_ACCESS_MODE=https", repair_text)
        self.assertIn("error_page 497 =308 https://{host}:{port}$request_uri", repair_text)
        self.assertIn("deploy/repair-panel-access.sh", upgrade_text)

    def test_final_output_reports_existing_https_correctly(self):
        text = EC2.read_text(encoding="utf-8")
        self.assertIn('PANEL_HTTPS_STATUS="включён"', text)
        self.assertIn('HTTPS:           $PANEL_HTTPS_STATUS', text)

    def test_purge_uses_safe_working_directory_and_english_confirmation(self):
        text = PURGE.read_text(encoding="utf-8")
        self.assertIn("cd /", text)
        self.assertIn("DELETE ALL", text)
        self.assertIn("wait_for_package_manager", text)

    def test_readme_documents_ip_install_and_later_https(self):
        text = README.read_text(encoding="utf-8")
        self.assertIn("Первоначальная установка больше не требует домена", text)
        self.assertIn("Безопасность → Доступ к панели", text)
        self.assertIn("http://SERVER_IP:61443", text)


class ServicePermissionsTest(unittest.TestCase):
    def test_web_service_can_write_managed_nginx_files(self):
        text = (ROOT / "deploy" / "install-service.sh").read_text(encoding="utf-8")
        self.assertIn("/etc/nginx", text)
        self.assertIn("/var/www/sg-panel-placeholder", text)

    def test_upgrade_installs_wgcf_helper_without_breaking_panel_upgrade(self):
        text = (ROOT / "install-or-upgrade.sh").read_text(encoding="utf-8")
        self.assertIn("deploy/install-wgcf-cli.sh", text)
        self.assertIn("WARNING: wgcf-cli was not installed", text)

    def test_service_creates_read_write_paths_before_unit_file(self):
        text = (ROOT / "deploy" / "install-service.sh").read_text(encoding="utf-8")
        mkdir_pos = text.index("mkdir -p")
        unit_pos = text.index('cat > "$SERVICE_FILE" <<UNIT')
        self.assertLess(mkdir_pos, unit_pos)
        self.assertIn("/var/www/sg-panel-placeholder", text[mkdir_pos:unit_pos])
        self.assertIn("/usr/local/etc/xray", text[mkdir_pos:unit_pos])
        self.assertIn("/etc/nginx", text[mkdir_pos:unit_pos])


if __name__ == "__main__":
    unittest.main()
