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
  script_oid("1.3.6.1.4.1.25623.1.0.130403");
  script_version("2025-09-03T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the Password Complexity Is Set Correctly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.1 Ensure That the Password Complexity Is Set Correctly (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.1 Ensure That the Password Complexity Is Set Correctly (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.1 Ensure That the Password Complexity Is Set Correctly (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.1 Ensure That the Password Complexity Is Set Correctly (Requirement)");

  script_tag(name:"summary", value:"Simple passwords, including short passwords and passwords
containing only digits or letters, are easy to guess by brute force cracking tools. As such, users
are required to set complex passwords. For service scenarios with high security requirements,
follow industry best practices. For example, ensure that the password contains at least 14
characters. For a combination of four types of characters, it is recommended that each type of
character appear at least once to prevent passwords from being easily cracked.

openEuler requires that the passwords must meet the following complexity requirements:
1. Contain at least eight characters.
2. Contains at least three types of the following characters:
3. At least one lowercase letter
4. At least one uppercase letter
5. At least one digit
6. At least one of the following special characters: space and ` ~ ! @ # $ % ^ & * ( ) - _ = +
 <pipe> [ { } ] <semicolon> : ' <quote> , < . > / ?

To ensure ease of use in different scenarios, the enforce_for_root and retry values are not
configured in openEuler by default. Configure them as required.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That the Password Complexity Is Set Correctly";

solution = "Method 1:
1. You can set the password complexity by modifying the /etc/pam.d/password-auth and
/etc/pam.d/system-auth files. For example, in the /etc/pam.d/system-auth file, the configuration
fields are as follows:
# vim /etc/pam.d/system-auth
password    requisite     pam_pwquality.so minlen=8 minclass=3 enforce_for_root try_first_pass
local_users_only retry=3 dcredit=0 ucredit=0 lcredit=0 ocredit=0
Method 2:
1. Configure the following fields in the /etc/security/pwquality.conf file:
# vim /etc/security/pwquality.conf
minlen=8
minclass=3
retry=3
dcredit=0
ucredit=0
lcredit=0
ocredit=0
enforce_for_root
";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep pam_pwquality /etc/pam.d/system-auth | grep -vE "^\\s*#|minlen=[0-7]"';

expected_value = 'The output should contain "minlen" and contain "minclass=3" and contain "enforce_for_root" and contain "retry=3" and contain "dcredit=0" and contain "ucredit=0" and contain "lcredit=0" and contain "ocredit=0"';

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
# CHECK : Verify command `grep system-auth /etc/pam.d/ -r`
# ------------------------------------------------------------------
step_cmd = 'grep pam_pwquality /etc/pam.d/system-auth | grep -vE "^\\s*#|minlen=[0-7]"';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(strstr(actual_value, 'minlen') && strstr(actual_value, 'minclass=3') && strstr(actual_value, 'enforce_for_root') && strstr(actual_value, 'retry=3') && strstr(actual_value, 'dcredit=0') && strstr(actual_value, 'ucredit=0') && strstr(actual_value, 'lcredit=0') && strstr(actual_value, 'ocredit=0')){
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
