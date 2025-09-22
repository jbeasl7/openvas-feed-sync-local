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
  script_oid("1.3.6.1.4.1.25623.1.0.130397");
  script_version("2025-08-22T15:40:55+0000");
  script_tag(name:"last_modification", value:"2025-08-22 15:40:55 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That Passwords Do Not Contain User Names");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.4 Ensure That Passwords Do Not Contain User Names (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.4 Ensure That Passwords Do Not Contain User Names (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.4 Ensure That Passwords Do Not Contain User Names (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.4 Ensure That Passwords Do Not Contain User Names (Requirement)");

  script_tag(name:"summary", value:"To ensure user security, you must configure passwords that do
not contain user names.

If a password is the same as the user name or the user name in reverse order, or contains the user
name, attackers can guess the password easily. This requirement is not exerted on passwords of
users whose names have three or less characters. However, you are advised to set user names with a
proper length.

If a user name contains more than three characters, the password cannot be any of the following
ones:

1. User name
2. User name in reverse order
3. Characters containing the user name");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That Passwords Do Not Contain User Names";

solution = 'pam_pwquality.so is a PAM module that checks the password quality. By default, it
supports passwords not containing user name characters. Therefore, if the configuration file
contains the module and usercheck is not set to 0, the corresponding function can be implemented.

Modify the /etc/pam.d/password-auth and /etc/pam.d/system-auth files. For example, in the
/etc/pam.d/system-auth file, if the usercheck=0 field exists, delete it. The configuration fields
are as follows:

# vim /etc/pam.d/system-auth
password    requisite     pam_pwquality.so minlen=8 minclass=3 enforce_for_root try_first_pass
local_users_only retry=3 dcredit=0 ucredit=0 lcredit=0 ocredit=0';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# ( grep -Eq \'^[[:space:]]*password[[:space:]]+.*pam_pwquality\\.so\' /etc/pam.d/system-auth \\   && ! grep -Eq \'^[[:space:]]*password[[:space:]]+.*pam_pwquality\\.so.*\\busercheck=0\\b\' /etc/pam.d/system-auth ) \\   && grep -E \'^[[:space:]]*password[[:space:]]+.*pam_pwquality\\.so.*\' /etc/pam.d/system-auth

2. Run the command in the terminal:
# ( grep -Eq \'^[[:space:]]*password[[:space:]]+.*pam_pwquality\\.so\' /etc/pam.d/password-auth \\   && ! grep -Eq \'^[[:space:]]*password[[:space:]]+.*pam_pwquality\\.so.*\\busercheck=0\\b\' /etc/pam.d/password-auth ) \\   && grep -E \'^[[:space:]]*password[[:space:]]+.*pam_pwquality\\.so.*\' /etc/pam.d/password-auth';

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
# CHECK 1 :  Check system-auth
# ------------------------------------------------------------------

step_cmd_check_1 = '( grep -Eq \'^[[:space:]]*password[[:space:]]+.*pam_pwquality\\.so\' /etc/pam.d/system-auth \\   && ! grep -Eq \'^[[:space:]]*password[[:space:]]+.*pam_pwquality\\.so.*\\busercheck=0\\b\' /etc/pam.d/system-auth ) \\   && grep -E \'^[[:space:]]*password[[:space:]]+.*pam_pwquality\\.so.*\' /etc/pam.d/system-auth';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check password-auth
# ------------------------------------------------------------------

step_cmd_check_2 = '( grep -Eq \'^[[:space:]]*password[[:space:]]+.*pam_pwquality\\.so\' /etc/pam.d/password-auth \\   && ! grep -Eq \'^[[:space:]]*password[[:space:]]+.*pam_pwquality\\.so.*\\busercheck=0\\b\' /etc/pam.d/password-auth ) \\   && grep -E \'^[[:space:]]*password[[:space:]]+.*pam_pwquality\\.so.*\' /etc/pam.d/password-auth';
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