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
  script_oid("1.3.6.1.4.1.25623.1.0.130385");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That Different Group IDs Are Initially Assigned to Different Users");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.3 Ensure That Different Group IDs Are Initially Assigned to Different Users (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.3 Ensure That Different Group IDs Are Initially Assigned to Different Users (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.3 Ensure That Different Group IDs Are Initially Assigned to Different Users (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.3 Ensure That Different Group IDs Are Initially Assigned to Different Users (Requirement)");

  script_tag(name:"summary", value:"The initial login groups of different users must be different.
If a user needs to access files in another group, you need to run a command to add the user to the
group. In most cases, if the file permission and the folder permission are set to 640 and 750,
respectively, users in the same group can access the group files. Therefore, if two irrelevant
users are set to the same group, the files may be read or even tampered with.

By default, different group IDs are allocated to different users in openEuler.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That Different Group IDs Are Initially Assigned to Different Users";

solution = "1.When adding a user, do not use the -g option to specify a group. Instead, enable the
system to automatically allocate a new group. The -U option indicates that a new user group needs
to be created. By default, the -U option is not required.

# useradd test

Or

# useradd test

2. If the new user needs to be added to another group, you can use the -G option to specify the
group. The following command creates a test1 group for the test1 user as the default login group.
In addition, the test1 user is added to the test user group.

# useradd -G test test1

Run the following commands to check whether the default login groups of test1 and test are
different:

# cat /etc/passwd <pipe> grep test
test:x:1007:1007::/home/test:/bin/bash
test1:x:1008:1008::/home/test1:/bin/bash

Run the following command to find that the test1 user is also added to the test group:
# id test1
uid=1008(test1) gid=1008(test1) groups=1008(test1),1007(test)

After logging in to the system using the test1 user (or switching to the test1 user using the su
command), you can run the newgrp command to add the user to the test group. After the command is
executed, the current group ID changes to the ID of the test group, but the group ID in /etc/passwd
does not change.
# su test1
$ newgrp test
$ id
uid=1008(test1) gid=1007(test) groups=1007(test),1008(test1)
context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

2.If an existing user needs to be added to another group, run the following command:
# usermod -a -G root test1

After the command is executed, the test1 user is added to the root group. The command output is as
follows:
# id test1
uid=1008(test1) gid=1008(test1) groups=1008(test1),0(root),1007(test)";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# cat /etc/passwd | awk -F ":" "{a[\\$4]++}END{for(i in a){if(a[i]!=1 && i!=0){print i, a[i]}}}"';

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
# CHECK : Check /etc/passwd
# ------------------------------------------------------------------

step_cmd = 'cat /etc/passwd | awk -F ":" "{a[\\$4]++}END{for(i in a){if(a[i]!=1 && i!=0){print i, a[i]}}}"';
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