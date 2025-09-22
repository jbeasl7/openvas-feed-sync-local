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
  script_oid("1.3.6.1.4.1.25623.1.0.130291");
  script_version("2025-09-03T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That Rotation Is Enabled for Audit Logs");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.2 Ensure That Rotation Is Enabled for Audit Logs (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.2 Ensure That Rotation Is Enabled for Audit Logs (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.2 Ensure That Rotation Is Enabled for Audit Logs (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.2 Ensure That Rotation Is Enabled for Audit Logs (Requirement)");

  script_tag(name:"summary", value:"max_log_file_action decides the action taken when the size of a
log file reaches the upper limit. By default, ROTATE is configured in openEuler, indicating that a
new log file is created when the size of a log file reaches the upper limit and the original log
file is not deleted.

num_logs specifies the maximum number of log files that can be created when rotation is enabled. If
the number of log files reaches the upper limit, the earliest log file will be overwritten. The
default value is 5 in openEuler.

The value of num_logs ranges from 0 to 99. Values 0 and 1 indicate that rotation is not enabled.

The possible values of max_log_file_action are as follows.

IGNORE: The audit daemon ignores the upper limit of the log file size and continues to record logs
in the file.

SYSLOG: In addition to the behavior for IGNORE, the audit daemon records a log to syslog when the
upper limit is reached.

SUSPEND: The audit daemon stops recording logs when the size of a log file reaches the upper limit.

ROTATE: The audit daemon creates a log file to continue recording logs when the size of a log file
reaches the upper limit. If the number of log files reaches num_logs, the oldest log file is
overwritten.

KEEP_LOGS: Similar to the behavior for ROTATE, the audit daemon ignores the setting of num_logs and
creates a log file.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That Rotation Is Enabled for Audit Logs";

solution = "Change the values of max_log_file_action and num_logs in the /etc/audit/auditd.conf
file.

# vim /etc/audit/auditd.conf
num_logs = <file numbers>
max_log_file_action = <action type>

Restart the auditd service for the configuration to take effect.

# service auditd restart
Stopping logging: [  OK  ]
Redirecting start to /bin/systemctl start auditd.service";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -iE "max_log_file_action|num_logs" /etc/audit/auditd.conf | grep -vE "^\\s*#"';

expected_value = 'The output should match the pattern "num_logs\\s*=\\s*([2-9]|[1-9][0-9])" and contain "max_log_file_action = ROTATE"';

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
# CHECK : Check current value of max_log_file_action
# ------------------------------------------------------------------
step_cmd = 'grep -iE "max_log_file_action|num_logs" /etc/audit/auditd.conf | grep -vE "^\\s*#"';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value =~ 'num_logs\\s*=\\s*([2-9]|[1-9][0-9])' && strstr(actual_value, 'max_log_file_action = ROTATE')){
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
