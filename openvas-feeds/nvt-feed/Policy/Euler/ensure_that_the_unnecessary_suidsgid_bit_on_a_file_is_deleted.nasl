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
  script_oid("1.3.6.1.4.1.25623.1.0.130426");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the Unnecessary SUID/SGID Bit on a File Is Deleted");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.13 Ensure That the Unnecessary SUID/SGID Bit on a File Is Deleted (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.13 Ensure That the Unnecessary SUID/SGID Bit on a File Is Deleted (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.13 Ensure That the Unnecessary SUID/SGID Bit on a File Is Deleted (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.13 Ensure That the Unnecessary SUID/SGID Bit on a File Is Deleted (Requirement)");

  script_tag(name:"summary", value:"SUID (set user ID) and SGID (set group ID) are special
permission bits used to control program permissions in UNIX and UNIX-like OSs, including Linux. It
is important to ensure that files do not contain unnecessary SUID or SGID bits to improve system
security. These bits allow files to run with the permissions of the file owner or owner group to
which the files belong, which may cause potential security risks.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That the Unnecessary SUID/SGID Bit on a File Is Deleted";

solution = "Find files with SUID or SGID bits and review them to determine whether these bits are
necessary. Generally, only some specific system tools or programs require SUID or SGID bits.

If a file does not require the SUID or SGID bit, delete the file or remove the SUID and SGID bits
on the file.

# rm -rf /path/to/file

Or

# chmod u-s,g-s /path/to/file";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# find / \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null';

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
# CHECK : Verify command find / \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null
# ------------------------------------------------------------------

step_cmd = 'find / \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null';
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