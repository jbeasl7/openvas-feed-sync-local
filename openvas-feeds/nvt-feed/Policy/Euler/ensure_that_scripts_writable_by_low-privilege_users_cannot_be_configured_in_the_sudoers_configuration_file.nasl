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
  script_oid("1.3.6.1.4.1.25623.1.0.130414");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That Scripts Writable by Low-Privilege Users Cannot Be Configured in the sudoers Configuration File");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.6 Ensure That Scripts Writable by Low-Privilege Users Cannot Be Configured in the sudoers Configuration File (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.6 Ensure That Scripts Writable by Low-Privilege Users Cannot Be Configured in the sudoers Configuration File (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.6 Ensure That Scripts Writable by Low-Privilege Users Cannot Be Configured in the sudoers Configuration File (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.6 Ensure That Scripts Writable by Low-Privilege Users Cannot Be Configured in the sudoers Configuration File (Requirement)");

  script_tag(name:"summary", value:"The sudo command enables a specified common user to execute
certain programs with the root permission. The corresponding configuration file is /etc/sudoers.
The administrator can configure rules to enable some scripts or binary files to run with the root
permission. Therefore, only the root user can write scripts configured using the sudo command.
Scripts writable by low-privilege users cannot be configured. If such type of script is configured,
the user can modify the scripts to implement privilege escalation.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That Scripts Writable by Low-Privilege Users Cannot Be Configured in the sudoers Configuration File";

solution = "For example, if the script in the /etc/sudoers configuration file is writable by
low-privilege users, the users need to rectify this issue based on the actual service scenario.

1. Method
Modify the script file permission in the /etc/sudoers configuration file to remove the write
permission of low-privilege users to prevent privilege escalation.

2. Method 2
Modify the /etc/sudoers configuration file to delete the script files that can be configured by
low-privilege users to prevent low-privilege users from performing privilege escalation.";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -E \'^\\s*[^#].*\\(root\\)\' /etc/sudoers | awk \'{print \\$3}\' | while read cmd; do if [ -e "$cmd" ]; then perms=$(stat -c "%a %U" "$cmd"); perm=${perms%% *}; user=${perms#* }; if [ "$user" != "root" ] || [ $(( (perm & 022) )) -ne 0 ]; then echo "$cmd $perm $user"; fi; fi; done';

expected_value = 'The output should be empty';

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
# CHECK : Verify command `grep "(root)" /etc/sudoers`
# ------------------------------------------------------------------

step_cmd = 'grep -E \'^\\s*[^#].*\\(root\\)\' /etc/sudoers | awk \'{print \\$3}\' | while read cmd; do if [ -e "$cmd" ]; then perms=$(stat -c "%a %U" "$cmd"); perm=${perms%% *}; user=${perms#* }; if [ "$user" != "root" ] || [ $(( (perm & 022) )) -ne 0 ]; then echo "$cmd $perm $user"; fi; fi; done';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(!actual_value){
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