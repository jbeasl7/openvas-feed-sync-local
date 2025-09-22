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
  script_oid("1.3.6.1.4.1.25623.1.0.130412");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the su Command Inherits the User Environment Variables Without Escalating Privileges");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.8 Ensure That the su Command Inherits the User Environment Variables Without Escalating Privileges (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.8 Ensure That the su Command Inherits the User Environment Variables Without Escalating Privileges (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.8 Ensure That the su Command Inherits the User Environment Variables Without Escalating Privileges (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.8 Ensure That the su Command Inherits the User Environment Variables Without Escalating Privileges (Requirement)");

  script_tag(name:"summary", value:"The su command enables a common user to have the permissions of
the superuser or other users. It is often used for switching the user from a common user to the
root user. The su command provides a convenient way for users to change their identities. However,
if the su command is run without restrictions, the system may be exposed to potential risks. When
the su command is used to switch users, the PATH variable is not automatically set for users. If
the system automatically initializes the environment variable PATH after you run the su command to
switch the user, privilege escalation caused by inheritance of the environment variable PATH can be
effectively prevented.

By default, after the su command is executed in openEuler, PATH is automatically initialized.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That the su Command Inherits the User Environment Variables Without Escalating Privileges";

solution = "Add the following configuration to the /etc/login.defs configuration file so that the
environment variable PATH is automatically initialized after user switching.

# vim /etc/login.defs
ALWAYS_SET_PATH=yes";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -E "^ALWAYS_SET_PATH=yes" /etc/login.defs || true';

expected_value = 'The output should not be empty';

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
# CHECK : Verify command grep -E "^ALWAYS_SET_PATH=yes" /etc/login.defs || true
# ------------------------------------------------------------------

step_cmd = 'grep -E "^ALWAYS_SET_PATH=yes" /etc/login.defs || true';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value){
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