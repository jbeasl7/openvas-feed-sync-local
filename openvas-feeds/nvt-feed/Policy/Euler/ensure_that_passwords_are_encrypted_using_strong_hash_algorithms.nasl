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
  script_oid("1.3.6.1.4.1.25623.1.0.130396");
  script_version("2025-08-22T15:40:55+0000");
  script_tag(name:"last_modification", value:"2025-08-22 15:40:55 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That Passwords Are Encrypted Using Strong Hash Algorithms");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.5 Ensure That Passwords Are Encrypted Using Strong Hash Algorithms (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.5 Ensure That Passwords Are Encrypted Using Strong Hash Algorithms (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.5 Ensure That Passwords Are Encrypted Using Strong Hash Algorithms (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.5 Ensure That Passwords Are Encrypted Using Strong Hash Algorithms (Requirement)");

  script_tag(name:"summary", value:"For system security, passwords cannot be stored in plaintext in
the system and must be encrypted. Irreversible cryptographic algorithms must be used in scenarios
where passwords do not need to be recovered. If a password is encrypted with a weak algorithm,
attackers can increase the computing power to obtain the original character strings with the same
hash result before the password is changed. No matter whether the character strings are the same as
the original password, attackers can use them for login. Currently, for a password encrypted using
weak algorithms in the industry, such as MD5 and SHA1, attackers can generate two different
original texts of the same ciphertext with limited computing power. Using a strong hash algorithm
to encrypt user passwords can make it more difficult for attackers to crack passwords, reducing the
risk of password leakage. You can configure the encryption algorithm for passwords based on the
actual requirements. However, the algorithm strength cannot be lower than that of SHA512.

The SHA512 algorithm is used in openEuler to encrypt passwords by default, which meets security
requirements.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That Passwords Are Encrypted Using Strong Hash Algorithms";

solution = 'You can enable the function of using strong hash encryption algorithms for passwords
by modifying the /etc/pam.d/password-auth and /etc/pam.d/system-auth files.

For example, in the /etc/pam.d/system-auth file, the configuration fields are as follows:

# vim /etc/pam.d/system-auth
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# grep -E "pam_unix.so.*sha512" /etc/pam.d/system-auth

2. Run the command in the terminal:
# grep -E "pam_unix.so.*sha512" /etc/pam.d/password-auth';

expected_value = '1. The output should contain "pam_unix.so sha512"
2. The output should contain "pam_unix.so sha512"';

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
# CHECK 1 :  Check system-auth hash
# ------------------------------------------------------------------

step_cmd_check_1 = 'grep -E "pam_unix.so.*sha512" /etc/pam.d/system-auth';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(strstr(step_res_check_1, 'pam_unix.so sha512')){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check password-auth hash
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep -E "pam_unix.so.*sha512" /etc/pam.d/password-auth';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(strstr(step_res_check_2, 'pam_unix.so sha512')){
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