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
  script_oid("1.3.6.1.4.1.25623.1.0.130392");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That a User Is Locked After a Specified Number of Login Failures");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_add_preference(name:"Unlock Time", type:"entry", value:"300", id:1);
  script_add_preference(name:"Deny", type:"entry", value:"3", id:2);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.3 Identity Authentication: 2.3.1 Ensure That a User Is Locked After a Specified Number of Login Failures (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.3 Identity Authentication: 2.3.1 Ensure That a User Is Locked After a Specified Number of Login Failures (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.3 Identity Authentication: 2.3.1 Ensure That a User Is Locked After a Specified Number of Login Failures (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.3 Identity Authentication: 2.3.1 Ensure That a User Is Locked After a Specified Number of Login Failures (Requirement)");
  script_tag(name:"summary", value:"If a user fails to log in to the system for a specified number
of consecutive times, the system locks the user. That is, the user is not allowed to log in to the
system for a specified period of time to prevent malicious system password cracking. During the
lockout period, any input is considered invalid and the lockout duration is not re-counted due to
another input. When the user is unlocked, records of login attempts are cleared. The preceding
settings protect passwords from being forcibly cracked and improve system security. By default, the
number of consecutive login failures is 3. After three login failures, the user is locked for 300s
by default.

To ensure ease of use of the community version in different scenarios, the openEuler distribution
does not provide this security function by default. You need to configure the default number of
failures and lockout duration based on the actual application scenario and requirements.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That a User Is Locked After a Specified Number of Login Failures";

solution = "You can change the values following deny= and unlock_time= in the
/etc/pam.d/password-auth and /etc/pam.d/system-auth files to configure the maximum number of
consecutive login failures and lockout duration, respectively. For example, in the
/etc/pam.d/system-auth file, the configuration fields are as follows:

# vim /etc/pam.d/system-auth
auth  required  pam_faillock.so preauth audit deny=3 even_deny_root unlock_time=300
auth  [default=die] pam_faillock.so authfail audit deny=3 even_deny_root unlock_time=300
auth  sufficient  pam_faillock.so authsucc audit deny=3 even_deny_root unlock_time=300";

check_type = "SSH_Cmd";

unlock_time = script_get_preference("Unlock Time");
deny = script_get_preference("Deny");

action = '1. Run the command in the terminal:
# grep deny='+ deny +' /etc/pam.d/system-auth 2>/dev/null

2. Run the command in the terminal:
# grep unlock_time='+ unlock_time +'  /etc/pam.d/system-auth 2>/dev/null';

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
# CHECK 1: Check deny value in pam file
# ------------------------------------------------------------------

step_cmd_check_1 = 'grep deny=' + deny + ' /etc/pam.d/system-auth 2>/dev/null';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2: Check unlock time in pam file
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep unlock_time=' + unlock_time + ' /etc/pam.d/system-auth 2>/dev/null';
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
