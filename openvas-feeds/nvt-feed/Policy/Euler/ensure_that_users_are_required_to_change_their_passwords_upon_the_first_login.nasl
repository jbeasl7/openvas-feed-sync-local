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
  script_oid("1.3.6.1.4.1.25623.1.0.130402");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That Users Are Required to Change Their Passwords Upon the First Login");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_add_preference(name:"User", type:"entry", value:"test", id:1);


  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.11 Ensure That Users Are Required to Change Their Passwords Upon the First Login (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.11 Ensure That Users Are Required to Change Their Passwords Upon the First Login (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.11 Ensure That Users Are Required to Change Their Passwords Upon the First Login (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.11 Ensure That Users Are Required to Change Their Passwords Upon the First Login (Requirement)");

  script_tag(name:"summary", value:"If a password, such as one reset by an administrator, is not
promptly changed in the service environment when it is not set by the user, it may lead to low-cost
attacks. Therefore, it is necessary for users to change their password upon their initial login.
However, the root user's password is not subject to this rule.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That Users Are Required to Change Their Passwords Upon the First Login";

solution = "After resetting the password of a user, the administrator can run the following
command to set the password to expire immediately. The user is required to change the password of
the user upon the next login. The password that expires in this mode is not restricted by the
password change validity period (35 days by default). The test user is used as an example.

# passwd -e test";

check_type = "SSH_Cmd";

action = "Run the command in the terminal:
# awk -F: '/^{Username}:/ { print $3 }' /etc/shadow";

expected_value = 'The output should be equal to "0"';

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
# CHECK : Verify command awk -F: '/^{Username}:/ { print $3 }' /etc/shadow
# ------------------------------------------------------------------

user_name = script_get_preference("User");
step_cmd = 'awk -F: \'/^' + user_name + ':/ { print \\$3 }\' /etc/shadow';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value == '0'){
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