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
  script_oid("1.3.6.1.4.1.25623.1.0.130386");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Allow Non-root Users with UID 0");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.4 Do Not Allow Non-root Users with UID 0 (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.4 Do Not Allow Non-root Users with UID 0 (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.4 Do Not Allow Non-root Users with UID 0 (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.4 Do Not Allow Non-root Users with UID 0 (Requirement)");

  script_tag(name:"summary", value:"The user with UID 0 is the super administrator user in the
Linux system. By convention, the user name is root. The UID of a non-root user cannot be 0. If the
UID of the root user is changed to another value and the UID of another user (for example, the test
user) is changed to 0, the test user is granted the permissions of the super administrator. The
following main problems may occur:

1. Security scanning tools commonly used in the industry consider that the test user has an invalid
UID.
2. The management cost is increased. The system may be damaged if a user does not realize that the
test user is granted with the permissions of the super administrator.

By default, openEuler does not have non-root users with UID 0.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Allow Non-root Users with UID 0";

solution = "Change the UID field of the user in the /etc/passwd file and restart the system.
Ensure that the new UID is unique.

Note: The usermod command can be used to change the UID of a user. However, if the UID of the user
to be changed is 0, an error is displayed. The user whose UID is 0 is used by process 1. Therefore,
you can only manually modify the /etc/passwd file.

# usermod -u 2000 test
usermod: user test is currently used by process 1";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# awk -F ":" "{if(\\$1!=\\"root\\" && \\$3==0){print \\$1, \\$3}}" /etc/passwd';

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
# CHECK : Verify command awk -F ":" "{if(\$1!=\"root\" && \$3==0){print \$1, \$3}}" /etc/passwd'`
# ------------------------------------------------------------------

step_cmd = 'awk -F ":" "{if(\\$1!=\\"root\\" && \\$3==0){print \\$1, \\$3}}" /etc/passwd';
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