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
  script_oid("1.3.6.1.4.1.25623.1.0.130292");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure Audit Rules for Privilege Escalation Operations");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.7 Configure Audit Rules for Privilege Escalation Operations (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.7 Configure Audit Rules for Privilege Escalation Operations (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.7 Configure Audit Rules for Privilege Escalation Operations (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.7 Configure Audit Rules for Privilege Escalation Operations (Recommendation)");

  script_tag(name:"summary", value:"In openEuler, logs of privilege escalation operations using the
sudo command are recorded in the /var/log/secure file by default. This file also records other
authentication-related security logs. If you want to audit privilege escalation operations using
sudo, you are advised to record logs related to sudo separately to /var/log/sudo.log, and then
audit and monitor these logs. Performing attacks by using sudo for privilege escalation is common.
You are advised to configure audit rules for tracing.

By default, audit rules for privilege escalation operations are not configured in openEuler. You
are advised to configure rules based on the actual service scenario.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure Audit Rules for Privilege Escalation Operations";

solution = "Modify the /etc/sudoers file and configure sudo logs to be separately recorded in the
/var/log/sudo.log file.
vim /etc/sudoers
Defaults logfile=/var/log/sudo.log

Create a rule file, for example, sudoaction.rules, in the /etc/audit/rules.d directory, and add
audit rules to the file. The /var/log/sudo.log file to be audited must be the log output file
configured in /etc/sudoers.

vim /etc/audit/rules.d/sudoaction.rules
-w /var/log/sudo.log -p wa -k <rules name>

Restart the auditd service for the rules to take effect.

# service auditd restart
Stopping logging: [  OK  ]
Redirecting start to /bin/systemctl start auditd.service";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# auditctl -l 2>/dev/null | grep -iE "sudo\\.log"';

expected_value = 'The output should be equal to "-w /var/log/sudo.log -p wa -k sudoaction"';

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
# CHECK : Check sudo\.log
# ------------------------------------------------------------------

step_cmd = 'auditctl -l 2>/dev/null | grep -iE "sudo\\.log"';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value == '-w /var/log/sudo.log -p wa -k sudoaction'){
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
