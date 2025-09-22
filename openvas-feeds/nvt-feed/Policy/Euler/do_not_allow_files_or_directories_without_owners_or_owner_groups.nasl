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
  script_oid("1.3.6.1.4.1.25623.1.0.130419");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Allow Files or Directories Without Owners or Owner Groups");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.1 Do Not Allow Files or Directories Without Owners or Owner Groups (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.1 Do Not Allow Files or Directories Without Owners or Owner Groups (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.1 Do Not Allow Files or Directories Without Owners or Owner Groups (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.1 Do Not Allow Files or Directories Without Owners or Owner Groups (Requirement)");

  script_tag(name:"summary", value:"Files or directories without owners or owner groups are not
allowed in the system. Generally, these files or directories refer to those whose previous owners
are deleted.

These files are security risks and may cause information leakage, occupy unnecessary drive space
and system resources, and affect service running.

In the container scenario, the container and host use different user namespaces. As a result, files
in a container may appear ownerless on the host. For the root file system of a container, the
parent directory of the root file system on the host is permission-controlled and can be accessed
by the root user only. In this case, ownerless directories or files are allowed.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Allow Files or Directories Without Owners or Owner Groups";

solution = "Run the rm command to delete the files without owners or owner groups. Before deleting
them, ensure that they are useless. Otherwise, run the chown command to change the owners or owner
groups to correct ones. The method is as follows:

# rm test -rf

Or

# chown test1:test1 test";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# find $(df -l | sed -n "2,\\$p" | awk "{print $6}") -xdev -nouser -o -nogroup 2>/dev/null';

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
# CHECK : Check directories without user groups
# ------------------------------------------------------------------

step_cmd = 'find $(df -l | sed -n "2,\\$p" | awk "{print $6}") -xdev -nouser -o -nogroup 2>/dev/null';
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