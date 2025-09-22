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
  script_oid("1.3.6.1.4.1.25623.1.0.130283");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure Audit Rules for File Access Control Permissions");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.18 Configure Audit Rules for File Access Control Permissions (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.18 Configure Audit Rules for File Access Control Permissions (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.18 Configure Audit Rules for File Access Control Permissions (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.18 Configure Audit Rules for File Access Control Permissions (Recommendation)");

  script_tag(name:"summary", value:"File access permission control is the basic permission
management in Linux. Different users can access different files after being authorized. This
prevents sensitive information leakage or file data tampering between users and prevents common
users from accessing high-permission files or configurations without authorization.

You are advised to audit and monitor system calls that modify file permissions and file owners in
the OS. If related audit is not configured, it is difficult to trace unauthorized modifications.

By default, audit rules for file access control permissions are not configured in openEuler. You
are advised to configure rules based on the actual service scenario.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure Audit Rules for File Access Control Permissions";

solution = "For a 32-bit system, create a rule file, for example, fileperm.rules, in the
/etc/audit/rules.d/ directory, and add audit rules to the file. <min uid> indicates the value of
UID_MIN (the minimum value of UID when a user is added in the useradd mode) in the /etc/login.defs
file. The default value is 1000 on openEuler.

# vim /etc/audit/rules.d/fileperm.rules
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=<min uid> -F auid!=unset -k
<rules name>
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=<min uid> -F
auid!=unset -k <rules name>
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S
fremovexattr -F auid>=<min uid> -F auid!=unset -k <rules name>

For a 64-bit system, add configuration related to arch=b64:

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=<min uid> -F auid!=unset -k
<rules name>
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=<min uid> -F
auid!=unset -k <rules name>
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S
fremovexattr -F auid>=<min uid> -F auid!=unset -k <rules name>

To ensure compatibility, the configuration related to arch=b32 in the 64-bit system must be
retained. Restart the auditd service for the rules to take effect.

# service auditd restart
Stopping logging: [  OK  ]
Redirecting start to /bin/systemctl start auditd.service";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# auditctl -l | grep -E "\\-S\\s*" | grep -E "chmod|chown|setxattr|exattr"';

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
# CHECK : Check "chmod|chown|setxattr|exattr" in auditctl
# ------------------------------------------------------------------

step_cmd = 'auditctl -l | grep -E "\\-S\\s*" | grep -E "chmod|chown|setxattr|exattr"';
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
