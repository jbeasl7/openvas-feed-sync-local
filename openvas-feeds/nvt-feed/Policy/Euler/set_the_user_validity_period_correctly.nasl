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
  script_oid("1.3.6.1.4.1.25623.1.0.130384");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Set the User Validity Period Correctly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_add_preference(name:"User", type:"entry", value:"test", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.12 Set the User Validity Period Correctly (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.12 Set the User Validity Period Correctly (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.12 Set the User Validity Period Correctly (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.12 Set the User Validity Period Correctly (Recommendation)");
  script_tag(name:"summary", value:"The life cycle of a user must be managed based on the
application scenario. For example, the life cycle of a temporarily created management or
maintenance user or a user required by a periodic service ends when the service life cycle ends.
These users should be deleted when their life cycles end. However, they are easy to forget due to
management negligence. Therefore, it is recommended that the administrator set the user expiration
time when creating a user. (Note: System users are typically used for system services and program
running and do not meet login requirements. Therefore, the expiration time of system users can be
set based on service requirements.)

If a user is no longer needed but is not deleted or disabled, the user password may be disclosed or
the user may be used without permissions due to improper management of the user. For example, a
temporary user used for log maintenance should expire one month later. However, the user does not
expire after the due time. In this case, the administrator can still use the user to log in to the
system, thereby causing security risks.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Set the User Validity Period Correctly";

solution = "Run the usermod command to set the expiration time for a user. For example, test is
the user to be set, and yyyy-mm-dd indicates the expiration time.

# usermod -e yyyy-mm-dd test";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep "<user_name>" /etc/shadow | awk -F ":" \'{if(\\$8!=\\"\\"){print \\$8}}\'';

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
# CHECK : Verify command `grep "<user_name>" /etc/shadow | awk -F ":" '{if(\$8!=\"\"){print \$8}}'`
# ------------------------------------------------------------------

user_name = script_get_preference("User");
step_cmd = 'grep "' + user_name + '" /etc/shadow | awk -F ":" \'{if(\\$8!=\\"\\"){print \\$8}}\'';
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