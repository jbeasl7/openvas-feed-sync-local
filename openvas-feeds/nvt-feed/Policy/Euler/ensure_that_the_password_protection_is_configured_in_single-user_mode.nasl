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
  script_oid("1.3.6.1.4.1.25623.1.0.130400");
  script_version("2025-08-05T05:45:17+0000");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the Password Protection Is Configured in Single-User Mode");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.10 Ensure That the Password Protection Is Configured in Single-User Mode (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.10 Ensure That the Password Protection Is Configured in Single-User Mode (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.10 Ensure That the Password Protection Is Configured in Single-User Mode (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.10 Ensure That the Password Protection Is Configured in Single-User Mode (Requirement)");

  script_tag(name:"summary", value:"You can edit the GRUB startup menu and add the s or single
command to the Linux startup command line to enter the single-user mode, which is an emergency
rescue mode. In this mode, system data can be modified. For example, users can change the password
of the root user. In this case, the password of the root user needs to be verified when users enter
the single-user mode.

openEuler has been hardened by default. You must enter the password of the root user to enter the
single-user mode.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That the Password Protection Is Configured in Single-User Mode";

solution = '1. In the /usr/lib/systemd/system/rescue.service file, change the value of ExecStart
as follows:

# vim /usr/lib/systemd/system/rescue.service
ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue

2. In the /usr/lib/systemd/system/emergency.service file, change the value of ExecStart as follows:

# vim /usr/lib/systemd/system/emergency.service
ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# grep /systemd-sulogin-shell /usr/lib/systemd/system/rescue.service | grep ExecStart= | grep rescue

2. Run the command in the terminal:
# grep /systemd-sulogin-shell /usr/lib/systemd/system/emergency.service | grep ExecStart= | grep emergency';

expected_value = '1. The output should not be empty
2. The output should not be empty';

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
# CHECK 1 :  Verify command `grep /systemd-sulogin-shell /usr/lib/systemd/system/rescue.service | grep ExecStart= | grep rescue`
# ------------------------------------------------------------------

step_cmd_check_1 = 'grep /systemd-sulogin-shell /usr/lib/systemd/system/rescue.service | grep ExecStart= | grep rescue';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify command grep /systemd-sulogin-shell /usr/lib/systemd/system/emergency.service | grep ExecStart= | grep emergency`
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep /systemd-sulogin-shell /usr/lib/systemd/system/emergency.service | grep ExecStart= | grep emergency';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(step_res_check_2){
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