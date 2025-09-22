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
  script_oid("1.3.6.1.4.1.25623.1.0.130418");
  script_version("2025-09-03T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the umask Value Is Correct");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.5 Ensure That the umask Value Is Correct (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.5 Ensure That the umask Value Is Correct (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.5 Ensure That the umask Value Is Correct (Requirement)");

  script_tag(name:"summary", value:"The umask value is the mask for default file or directory
permissions. When a file or directory is created, its default permission is set to 777 minus the
umask value. For a file, its execute permission is also removed. If the umask value is set
improperly, the permission of new files may be too high or too low, affecting service running or
causing security risks.

Considering the usability of the community version in different scenarios, the umask value is not
configured in openEuler distributions by default. Configure a umask value as required.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That the umask Value Is Correct";

solution = "Perform modifications in either of the following ways:

1. Modify the umask field in the /etc/bashrc file. The modification affects all users upon next
login.

# vim /etc/bashrc
umask 0077
2. Modify or add the umask field in the ~/.bashrc file. The configuration affects only the current
user upon next login. If the configuration in the file is different from that in the /etc/bashrc
file, the configuration in ~/.bashrc is used.

# vim /home/test/.bashrc
umask 0077";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -vE "^\\s*#" /etc/bashrc ~/.bashrc | grep -iE "umask (077|0077)"';

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
# CHECK : Check "^umask in bashrc
# ------------------------------------------------------------------
step_cmd = 'grep -vE "^\\s*#" /etc/bashrc ~/.bashrc | grep -iE "umask (077|0077)"';
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
