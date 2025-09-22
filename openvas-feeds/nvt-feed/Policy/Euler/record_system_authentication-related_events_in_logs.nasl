# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# ------------------------------------------------------------------
# METADATA
# ------------------------------------------------------------------

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130300");
  script_version("2025-09-03T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Record System Authentication-related Events in Logs");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.2 Record System Authentication-related Events in Logs (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.2 Record System Authentication-related Events in Logs (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.2 Record System Authentication-related Events in Logs (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.2 Record System Authentication-related Events in Logs (Requirement)");

  script_tag(name:"summary", value:"System authentication-related events must be recorded to help
analyze users' logins and root permission usage and monitor suspicious system behaviors.

If system authentication-related event logs are not recorded, suspicious attacks, for example, the
attempt to guess the admin password to log in, cannot be analyzed based on the logs.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Record System Authentication-related Events in Logs";

solution = "Add the following configurations to /etc/rsyslog.conf:

# vim /etc/rsyslog.conf
*.info<semicolon>mail.none<semicolon>authpriv.none<semicolon>cron.none           /var/log/messages
authpriv.*                                         /var/log/secure

Run the following command to restart the service for the configuration to take effect:

# systemctl restart rsyslog.service";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep authpriv /etc/rsyslog.conf | grep -vE "^\\s*#|authpriv.none"';

expected_value = 'The output should not be empty';

# ------------------------------------------------------------------
# CONNECTION CHECK
# ------------------------------------------------------------------

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){

  report_ssh_error(title: title,
                   solution: solution,
                   action: action,
                   expected_value: expected_value,
                   check_type: check_type);
  exit(0);
}

# ------------------------------------------------------------------
# CHECK : Check the rsyslog
# ------------------------------------------------------------------
step_cmd = 'grep authpriv /etc/rsyslog.conf | grep -vE "^\\s*#|authpriv.none"';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value){
  compliant = "yes";
  comment = "Check passed";
}else{
  compliant = "no";
  comment = "Check failed";
}

# ------------------------------------------------------------------
# REPORT
# ------------------------------------------------------------------

report_audit(action: action,
             actual_value: actual_value,
             expected_value: expected_value,
             is_compliant: compliant,
             solution: solution,
             check_type: check_type,
             title: title,
             comment: comment);

exit(0);
