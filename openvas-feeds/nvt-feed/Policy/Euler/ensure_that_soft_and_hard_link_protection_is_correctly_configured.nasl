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
  script_oid("1.3.6.1.4.1.25623.1.0.130430");
  script_version("2025-08-12T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-12 05:40:06 +0000 (Tue, 12 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:56 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That Soft and Hard Link Protection Is Correctly Configured");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.16 Ensure That Soft and Hard Link Protection Is Correctly Configured (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.16 Ensure That Soft and Hard Link Protection Is Correctly Configured (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.16 Ensure That Soft and Hard Link Protection Is Correctly Configured (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.16 Ensure That Soft and Hard Link Protection Is Correctly Configured (Requirement)");

  script_tag(name:"summary", value:"In Linux, a soft or hard link is a file pointing to another
file (target). In other words, the target is opened once the link file is opened. Therefore, an
attacker can forge a soft link as a common user for a privileged user to execute, causing security
issues such as privilege escalation. The same issue occurs with hard links.

This rule requires soft and hard links to be hardened in the system. If the target file and link do
not belong to the same owner and the owner of the link does not have the execute permission on the
target file, whoever accesses the link is denied.

Therefore, a race condition exists. If a privileged process needs to create temporary file A in the
/tmp directory (generally, files created in a globally writable directory are vulnerable to attacks
because the permission control of other directories is strict), the first step is to check whether
the file exists. If not, a file is created and opened. In the interval between checking whether any
file exists and creating temporary file A, the attacker can create a soft link named A pointing to
key system file B, a file that can be accessed only by privileged administrators. When the
privileged process creates and accesses A, it actually accesses B. The attacker does not have the
permission on B. Instead, the attacker uses the privileged process to access B and can damage,
tamper with, and steal data from B.

In this example, the owner of both files A and B should be the root user. However, due to the race
condition attack, the owner of A becomes an attacker (a common user), the temporary file becomes a
link, and the owner of B is still the root user. As long as the privileged process has the
permission on B, B can be accessed through the soft link A.

By default, hard and soft links are protected in openEuler.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That Soft and Hard Link Protection Is Correctly Configured";

solution = 'Protection is enabled in openEuler by default and does not need to be configured.

1. You can temporarily enable or disable protection based on the actual scenario. The protection
status restores to the default value after a reboot.

To enable protection:

# sysctl -w fs.protected_symlinks=1
fs.protected_symlinks = 1

# sysctl -w fs.protected_hardlinks=1
fs.protected_hardlinks = 1

To disable protection:

# sysctl -w fs.protected_symlinks=0
fs.protected_symlinks = 0

# sysctl -w fs.protected_hardlinks=0
fs.protected_hardlinks = 0
2. You can add the following code to the /etc/sysctl.conf file and run sysctl -p /etc/sysctl.conf
to permanently enable or disable protection:

To enable protection:

# vim /etc/sysctl.conf
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

To disable protection:

# vim /etc/sysctl.conf
fs.protected_symlinks = 0
fs.protected_hardlinks = 0';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# sysctl fs.protected_symlinks

2. Run the command in the terminal:
# sysctl fs.protected_hardlinks';

expected_value = '1. The output should be equal to "fs.protected_symlinks = 1"
2. The output should be equal to "fs.protected_hardlinks = 1"';

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

overall_pass = FALSE;
actual_value = "";

# ------------------------------------------------------------------
# CHECK 1 :  Verify command `sysctl fs.protected_symlinks`
# ------------------------------------------------------------------

step_cmd_check_1 = 'sysctl fs.protected_symlinks';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 == 'fs.protected_symlinks = 1'){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify command `sysctl fs.protected_hardlinks`
# ------------------------------------------------------------------

step_cmd_check_2 = 'sysctl fs.protected_hardlinks';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(step_res_check_2 == 'fs.protected_hardlinks = 1'){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------
if(check_result_1 && check_result_2){
  overall_pass = TRUE;
}

if(overall_pass){
  compliant = "yes";
  comment = "All checks passed";
}else{
  compliant = "no";
  comment = "One or more checks failed";
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