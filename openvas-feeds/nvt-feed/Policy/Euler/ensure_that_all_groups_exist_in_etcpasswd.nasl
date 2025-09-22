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
  script_oid("1.3.6.1.4.1.25623.1.0.130378");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:54 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That All Groups Exist in /etc/passwd");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.7 Ensure That All Groups Exist in /etc/passwd (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.7 Ensure That All Groups Exist in /etc/passwd (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.7 Ensure That All Groups Exist in /etc/passwd (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.7 Ensure That All Groups Exist in /etc/passwd (Requirement)");

  script_tag(name:"summary", value:"All user groups in /etc/passwd must exist in the /etc/group
file. If the administrator manually modifies the two files, the user groups may be incorrectly set
due to human errors. If a user group in /etc/passwd does not exist in /etc/group, risks of user
group permission management may occur.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That All Groups Exist in /etc/passwd";

solution = "Analyze the cause of the mismatch between the two files. You can use either of the
following methods to rectify the fault:

1. Delete a user and add it again.

# userdel -r test
# useradd test

2. Delete or add a group (xxx indicates the value of gid).

# groupdel testgroup
# groupadd -g xxx testgroup";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -E -v "^(halt|sync|shutdown)" "/etc/passwd" | awk -F ":" "(\\$7 != \\"/bin/false\\" && \\$7 != \\"/sbin/nologin\\") {print \\$4}"| while read group; do grep -q -P "^.*?:[^:]*:$group:" "/etc/group"; if [ $? -ne 0 ]; then echo "group not found"; fi; done';

expected_value = 'The output should be empty';

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
# CHECK : Verify the long command
# ------------------------------------------------------------------

step_cmd = 'grep -E -v "^(halt|sync|shutdown)" "/etc/passwd" | awk -F ":" "(\\$7 != \\"/bin/false\\" && \\$7 != \\"/sbin/nologin\\") {print \\$4}"| while read group; do grep -q -P "^.*?:[^:]*:$group:" "/etc/group"; if [ $? -ne 0 ]; then echo "group not found"; fi; done';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(!actual_value){
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