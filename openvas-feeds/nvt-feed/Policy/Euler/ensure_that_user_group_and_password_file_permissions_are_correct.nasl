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
  script_oid("1.3.6.1.4.1.25623.1.0.130379");
  script_version("2025-09-03T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That User Group and Password File Permissions Are Correct");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.5 Ensure That User Group and Password File Permissions Are Correct (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.5 Ensure That User Group and Password File Permissions Are Correct (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.5 Ensure That User Group and Password File Permissions Are Correct (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.5 Ensure That User Group and Password File Permissions Are Correct (Requirement)");

  script_tag(name:"summary", value:"In the Linux OS-related information, such as users, passwords,
and user groups, is recorded in the configuration files in the /etc directory. Proper permissions
must be set for accessing these files. Otherwise, the files may be stolen or tampered with by
attackers.
The owner and owner group of these files must be root and the corresponding access permission must
be as follows:

/etc/passwd  is 644 (rw-r-r-)
/etc/shadow is 000 (---)
/etc/group is 644 (rw-r-r-)
/etc/gshadow is 000 (---)
/etc/passwd-  is 644 (rw-r-r-)
/etc/shadow- is 000 (---)
/etc/group- is 644 (rw-r-r-)
/etc/gshadow-  is 000 (---)

If the permission configuration is stricter than that in the table, common users may fail to read
information in the passwd or group configuration file during login. As a result, the login or
operation fails.

If the permission configuration is looser than that in the table, the configuration file
information may be stolen or tampered with by attackers.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That User Group and Password File Permissions Are Correct";

solution = "If the file permission does not meet the requirements, run the chown and chmod
commands to modify the file permission.

# chown root:root <passwd/group/shadow config file>
# chmod <access permissions> <passwd/group/shadow config file>";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# stat -c \'%n %U %G %A\' /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow-';

expected_value = 'The output should contain "/etc/passwd root root -rw-r--r--" and contain "/etc/shadow root root ----------" and contain "/etc/group root root -rw-r--r--" and contain "/etc/gshadow root root ----------" and contain "/etc/passwd- root root -rw-r--r--" and contain "/etc/shadow- root root ----------" and contain "/etc/group- root root -rw-r--r--" and contain "/etc/gshadow- root root ----------"';

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
# CHECK : Check stats
# ------------------------------------------------------------------
step_cmd = 'stat -c \'%n %U %G %A\' /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow-';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(strstr(actual_value, '/etc/passwd root root -rw-r--r--') && strstr(actual_value, '/etc/shadow root root ----------') && strstr(actual_value, '/etc/group root root -rw-r--r--') && strstr(actual_value, '/etc/gshadow root root ----------') && strstr(actual_value, '/etc/passwd- root root -rw-r--r--') && strstr(actual_value, '/etc/shadow- root root ----------') && strstr(actual_value, '/etc/group- root root -rw-r--r--') && strstr(actual_value, '/etc/gshadow- root root ----------')){
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
