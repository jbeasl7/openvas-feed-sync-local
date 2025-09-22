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
  script_oid("1.3.6.1.4.1.25623.1.0.130432");
  script_version("2025-09-03T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:56 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the Permissions on Important Files and Directories Are Minimized");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_add_preference(name:"File or Directory Name", type:"entry", value:"/home", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.14 Ensure That the Permissions on Important Files and Directories Are Minimized (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.14 Ensure That the Permissions on Important Files and Directories Are Minimized (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.14 Ensure That the Permissions on Important Files and Directories Are Minimized (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.14 Ensure That the Permissions on Important Files and Directories Are Minimized (Requirement)");

  script_tag(name:"summary", value:"According to the principle of least privilege, the minimum
access permission must be correctly set for key files or directories in the system, especially
those containing sensitive information. Only users with relevant permissions can access these files
or directories. If the file or directory permission is incorrectly configured, information about
files containing sensitive data may be disclosed. For example, if the access permission is greater
than or equal to 644, any user can access or even tamper with the file or directory. For a file
that is to be executed only by the root user and has the permission of 755, any user can execute
the file, causing privilege escalation risks.

Common types of files requiring access control include:

1.Executable files (binary files and scripts) and their directories. Improper permission
configuration may cause privilege escalation attacks.
2.Configuration files, key files, log files, data files that store sensitive information, temporary
files generated during system running, and static files. For such files, improper permission
configuration may increase information leakage risks.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That the Permissions on Important Files and Directories Are Minimized";

solution = "Run the chmod command to change the file permission:

# chmod 750 test
# ll test
-rwxr-x---. 1 root root 33 Nov  5 14:44 test";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# ls -l {{File or Directory Name}} 2>/dev/null';

expected_value = 'The output should not be empty';
file_or_directory_name = script_get_preference("File or Directory Name");

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
# CHECK : Verify command `ls -l test`
# ------------------------------------------------------------------

step_cmd = 'ls -l ' + file_or_directory_name + ' 2>/dev/null';
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
