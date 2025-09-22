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
  script_oid("1.3.6.1.4.1.25623.1.0.130433");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:56 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the Sticky Bit Is Set for Globally Writable Directories");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.4 Ensure That the Sticky Bit Is Set for Globally Writable Directories (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.4 Ensure That the Sticky Bit Is Set for Globally Writable Directories (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.4 Ensure That the Sticky Bit Is Set for Globally Writable Directories (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.4 Ensure That the Sticky Bit Is Set for Globally Writable Directories (Requirement)");

  script_tag(name:"summary", value:"The sticky bit of a common file is ignored by the kernel. The
sticky bit shows up as the execute permission flag of a directory and is indicated with t. If the
sticky bit set is for a directory, a user who is not root or the directory owner cannot delete
files or directories in the directory, unless the user owns the files or directories. However,
subdirectories do not inherit the sticky bit. The sticky bits must be set for globally writable
directories.

Users who have the write permission on a directory can delete files and subdirectories in the
directory even if they are not the owner of the files or do not have the read or write permission
on them.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That the Sticky Bit Is Set for Globally Writable Directories";

solution = "Run the chmod command to set the sticky bit of the directory. The value 1 sets the
sticky bit. Then, run the ll command to check whether the setting is successful. The example output
indicates that the x bit of other users is set to t.

# chmod 1777 test
# ll -d test
drwxrwxrwt. 2 root root 4096 Nov  4 14:31 test";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# find ./ -ignore_readdir_race -mount -type d -perm -0002 -a ! -perm -1000 2>/dev/null';

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
# CHECK : Verify command find ./ -ignore_readdir_race -mount -type d -perm -0002 -a ! -perm -1000 2>/dev/null
# ------------------------------------------------------------------

step_cmd = 'find ./ -ignore_readdir_race -mount -type d -perm -0002 -a ! -perm -1000 2>/dev/null';
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