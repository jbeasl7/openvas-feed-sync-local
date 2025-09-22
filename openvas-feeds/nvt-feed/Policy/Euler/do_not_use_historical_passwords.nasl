# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
# SPDX-License-Identifier: GPL-2.0-only

# ------------------------------------------------------------------
# METADATA
# ------------------------------------------------------------------

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130401");
  script_version("2025-07-11T15:43:14+0000");
  script_tag(name:"last_modification", value:"2025-07-11 15:43:14 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Use Historical Passwords");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.2 Do Not Use Historical Passwords (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.2 Do Not Use Historical Passwords (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.2 Do Not Use Historical Passwords (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.2 Do Not Use Historical Passwords (Requirement)");

  script_tag(name:"summary", value:"Using the same historical password frequently may cause
password leakage and attacks. To ensure user security, the function of disabling historical
passwords must be configured. The number of historical passwords that cannot be used must be
properly set based on the actual service scenario. The number must be no less than 5.

To ensure ease of use in different scenarios, the function of disabling historical passwords is not
configured in openEuler distributions by default. Configure this function based on service
requirements.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Use Historical Passwords";

solution = "You can disable the use of historical passwords by modifying the
/etc/pam.d/password-auth and /etc/pam.d/system-auth files.

1. Configure the following fields in the /etc/pam.d/system-auth file:

# vim /etc/pam.d/system-auth
password required pam_pwhistory.so use_authtok remember=5 enforce_for_root

2. Configure the following fields in the /etc/pam.d/password-auth file:
# vim /etc/pam.d/password-auth
password required pam_pwhistory.so use_authtok remember=5 enforce_for_root

The following table lists the configuration items in the pam_pwhistory.so file and corresponding
descriptions.

remember=5 is,
A password must be different from the last five passwords.

enforce_for_root is,
The configuration also applies to the root user.";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep pam_pwhistory /etc/pam.d/system-auth /etc/pam.d/password-auth';

expected_value = 'The output should match the pattern "\\/etc\\/pam\\.d\\/system-auth:.*remember=([5-9]|[1-9][0-9]+)\\s*enforce_for_root" and match the pattern "\\/etc\\/pam\\.d\\/password-auth:.*remember=([5-9]|[1-9][0-9]+)\\s*enforce_for_root"';

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

overall_pass = TRUE;
actual_value = "";

# ------------------------------------------------------------------
# CHECK : Verify command `grep pam_pwhistory /etc/pam.d/system-auth /etc/pam.d/password-auth`
# ------------------------------------------------------------------

step_cmd = 'grep pam_pwhistory /etc/pam.d/system-auth /etc/pam.d/password-auth';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value =~ "\/etc\/pam\.d\/system-auth:.*remember=([5-9]|[1-9][0-9]+)\s*enforce_for_root" &&
   actual_value =~ "\/etc\/pam\.d\/password-auth:.*remember=([5-9]|[1-9][0-9]+)\s*enforce_for_root"){
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

