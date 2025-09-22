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
  script_oid("1.3.6.1.4.1.25623.1.0.130277");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure Audit Rules for Privilege-Escalated Commands");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.5 Configure Audit Rules for Privilege-Escalated Commands (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.5 Configure Audit Rules for Privilege-Escalated Commands (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.5 Configure Audit Rules for Privilege-Escalated Commands (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.5 Configure Audit Rules for Privilege-Escalated Commands (Recommendation)");

  script_tag(name:"summary", value:"Users can call privilege-escalated commands (that is, commands
with SUID/SGID bits) to obtain the super administrator permissions. This operation is risky and
often exploited by attackers.
You are advised to audit and monitor privilege-escalated commands for future tracing.

By default, audit rules for privilege-escalated commands are not configured in openEuler. You are
advised to configure rules based on the actual service scenario.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure Audit Rules for Privilege-Escalated Commands";

solution = "Run the following command. The command searches for all privilege-escalated commands
(with SUID/SGID bits) in the system and generates corresponding rules in the
/etc/audit/rules.d/privileged.rules file based on the configured format. In the command, <min uid>
is the value of UID_MIN in /etc/login.defs, which can be set to 1000 in openEuler.

# find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) <pipe> awk '{print <quote>-a always,exit -F
path=<quote> $1 <quote> -F perm=x -F auid>=<min uid> -F auid!=unset -k <rules name><quote> }' >
/etc/audit/rules.d/privileged.rules

Restart the auditd service for the rules to take effect.

# service auditd restart
Stopping logging: [  OK  ]
Redirecting start to /bin/systemctl start auditd.service";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# find / -xdev -type f "(" -perm -4000 -o -perm -2000 ")" 2>/dev/null -exec sh -c "for f; do r=\\$(auditctl -l | grep \\"\\$f \\"); [ -z \\"\\$r\\" ] && echo \\"\\$f not set\\" || echo \\"\\$r\\"; done" sh {} +';

expected_value = 'The output should contain "not set"';

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
# CHECK : Check perm in auditctl
# ------------------------------------------------------------------

step_cmd = 'find / -xdev -type f "(" -perm -4000 -o -perm -2000 ")" 2>/dev/null -exec sh -c "for f; do r=\\$(auditctl -l | grep \\"\\$f \\"); [ -z \\"\\$r\\" ] && echo \\"\\$f not set\\" || echo \\"\\$r\\"; done" sh {} +';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(strstr(actual_value, 'not set')){
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
