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
  script_oid("1.3.6.1.4.1.25623.1.0.130374");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:54 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That a User Has Its Own Home Directory");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.6 Ensure That a User Has Its Own Home Directory (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.6 Ensure That a User Has Its Own Home Directory (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.6 Ensure That a User Has Its Own Home Directory (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.6 Ensure That a User Has Its Own Home Directory (Requirement)");

  script_tag(name:"summary", value:"Each user must have its own home directory for storing
user-related data. The owner of the home directory must be the user. If the owner of the home
directory is not the user, the user cannot read or write the home directory, or the user data
stored in the home directory can be read or tampered with by other users (such as the owner). If
the home directory does not exist, users cannot obtain their own environment configuration data
after login.

In openEuler, each user has its own home directory by default.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That a User Has Its Own Home Directory";

solution = "1. Delete the users without correct home directories.

# userdel -r test
userdel: test home directory (/home/test) not found

2. Run the useradd command to add a user (the home directory is automatically created):

# useradd test
# ll -d /home/test/
drwx------. 2 test test 4096 Feb  2 13:19 /home/test/";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -E -v "^(halt|sync|shutdown)" /etc/passwd | awk -F ":" "(\\$7 != \\"/bin/false\\" && \\$7 != \\"/sbin/nologin\\" && \\$7 != \\"/usr/sbin/nologin\\") {print \\$1 \\" \\" \\$6}" | while read name home; do if [ ! -d "$home" ]; then echo "No home folder \\"$home\\" of \\"$name\\"."; else owner=$(ls -l -d $home | awk -F " " "{print \\$3}"); if [ "$owner" != "$name" ]; then echo "\\"$home\\" is owned by $owner, not \\"$name\\"."; fi; fi; done';

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
# CHECK : Verify command `!/bin/bash`
# ------------------------------------------------------------------

step_cmd = 'grep -E -v "^(halt|sync|shutdown)" /etc/passwd | awk -F ":" "(\\$7 != \\"/bin/false\\" && \\$7 != \\"/sbin/nologin\\" && \\$7 != \\"/usr/sbin/nologin\\") {print \\$1 \\" \\" \\$6}" | while read name home; do if [ ! -d "$home" ]; then echo "No home folder \\"$home\\" of \\"$name\\"."; else owner=$(ls -l -d $home | awk -F " " "{print \\$3}"); if [ "$owner" != "$name" ]; then echo "\\"$home\\" is owned by $owner, not \\"$name\\"."; fi; fi; done';
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