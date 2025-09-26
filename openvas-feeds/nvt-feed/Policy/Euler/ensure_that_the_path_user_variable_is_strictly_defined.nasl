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
  script_oid("1.3.6.1.4.1.25623.1.0.130417");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the PATH User Variable Is Strictly Defined");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");

  script_add_preference(name:"Status", type:"radio", value:"Not Compliant;Compliant", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.20 Ensure That the PATH User Variable Is Strictly Defined (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.20 Ensure That the PATH User Variable Is Strictly Defined (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.20 Ensure That the PATH User Variable Is Strictly Defined (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.20 Ensure That the PATH User Variable Is Strictly Defined (Requirement)");

  script_tag(name:"summary", value:"In Linux, the PATH variable defines the path for searching for
executable files in the user context of the current user. For example, if a user runs the ls
command in any directory, the system searches for the ls command in the directories specified by
PATH and executes the command. The PATH variable in all user contexts cannot contain ., which
indicates the current directory. The directory must exist in the file system and meet the system
design expectation. A correct PATH value can effectively prevent the injection of malicious
commands, ensuring secure execution of system commands.

Therefore, the PATH variable must be set to a correct value. The default value in openEuler is as
follows:
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin

You can modify the PATH variable value based on the actual scenario and ensure it is correct.");

  exit(0);
}

include("policy_reporting_module.inc");

title = "Ensure That the PATH User Variable Is Strictly Defined";

solution = "The PATH environment variable is configured in the /etc/profile file and the .bashrc
or .bash_profile file in the user home directory. The former takes effect for all users, and the
latter takes effect for the current user.

Therefore, you can modify PATH-related fields in the two files to permanently change the PATH
value. For example:

# vim /etc/profile
export PATH=$PATH:<attach new path>

To temporarily change the PATH value for the current session, run the following command (the value
becomes invalid after the session is closed):

# export PATH=$PATH:<attach new path>

Or

# export PATH=<the whole of new path>";

check_type = "Manual";

action = "Needs manual check";

expected_value = script_get_preference("Status", id:1);

actual_value = expected_value;

# ------------------------------------------------------------------
# MANUAL CHECK
# ------------------------------------------------------------------

if(expected_value == "Compliant"){
  compliant = "yes";
  comment = "Marked as Compliant via Policy";
}
else if(expected_value == "Not Compliant"){
  compliant = "no";
  comment = "Marked as Non-Compliant via Policy.";
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
