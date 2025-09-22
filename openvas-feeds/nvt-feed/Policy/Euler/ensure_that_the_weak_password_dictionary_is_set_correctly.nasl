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
  script_oid("1.3.6.1.4.1.25623.1.0.130398");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the Weak Password Dictionary Is Set Correctly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.6 Ensure That the Weak Password Dictionary Is Set Correctly (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.6 Ensure That the Weak Password Dictionary Is Set Correctly (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.6 Ensure That the Weak Password Dictionary Is Set Correctly (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.6 Ensure That the Weak Password Dictionary Is Set Correctly (Requirement)");

  script_tag(name:"summary", value:"If a user password is weak, it is easy for attackers to guess
the password or crack it through dictionary attacks in a short period of time. A weak password
dictionary is a collection of passwords that are not strong enough and can be easily cracked
through guesses. Weak passwords include default passwords of the system and passwords that have
been leaked. The OS provides the weak password dictionary. When a password is created or changed,
the OS checks the password against the weak password dictionary. If a match is found, the password
cannot be used. The weak password dictionary can be updated and expanded. You can set a weak
password dictionary based on the actual service scenario.

During an upgrade, check whether the weak password dictionary check is enabled in earlier versions
or whether the weak password list is added in the new version.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That the Weak Password Dictionary Is Set Correctly";

solution = 'pam_pwquality.so is a PAM module that performs password quality detection. By default,
pam_pwquality.so supports weak password dictionary setting. You can perform the following
operations to update the weak password dictionary library:

1. Run the following command to export the dictionary library to the dictionary.txt file:

# cracklib-unpacker /usr/share/cracklib/pw_dict > dictionary.txt

2. After exporting and modifying the weak password dictionary, run the following command to update
the dictionary library:

# create-cracklib-dict dictionary.txt

3. Add other content, for example, custom.txt, to the original dictionary:

# create-cracklib-dict dictionary.txt custom.txt';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# grep pam_pwquality /etc/pam.d/system-auth 2>/dev/null | grep -E "dictcheck\\s*=\\s*0"

2. Run the command in the terminal:
# grep -E "^dictcheck\\s*=\\s*0" /etc/security/pwquality.conf 2>/dev/null';

expected_value = '1. The output should be empty
2. The output should be empty';

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
# CHECK 1 :  Check "dictcheck" and "pam_pwquality" in /etc/pam.d/system-auth
# ------------------------------------------------------------------

step_cmd_check_1 = 'grep pam_pwquality /etc/pam.d/system-auth 2>/dev/null | grep -E "dictcheck\\s*=\\s*0"';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(!step_res_check_1){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check "dictcheck" in /etc/security/pwquality.conf
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep -E "^dictcheck\\s*=\\s*0" /etc/security/pwquality.conf 2>/dev/null';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(!step_res_check_2){
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
