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
  script_oid("1.3.6.1.4.1.25623.1.0.130408");
  script_version("2025-08-28T05:39:05+0000");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure the SELinux Policy Correctly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.3 Configure the SELinux Policy Correctly (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.3 Configure the SELinux Policy Correctly (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.3 Configure the SELinux Policy Correctly (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.3 Configure the SELinux Policy Correctly (Recommendation)");

  script_tag(name:"summary", value:"SELinux policies are classified into basic policies and
user-defined policies.

Basic policies: policies defined in the basic policy package, including selinux-policy,
selinux-policy-targeted, and selinux-policy-mls.

User-defined policies: policies modified or added by users.

SELinux can implement process-level mandatory access control. System security can be improved by
configuring proper policies based on the minimum permission to restrict the behavior of key
applications and resources in the system. If no proper policy is configured for an application,
there may be two negative impacts:

1. If no policy is configured for an application, the application may run in unconfined_t or other
domains with high permissions. If the application is attacked, the system or services may be
greatly damaged.
2. If an improper policy is configured for an application, the application may fail to run properly.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure the SELinux Policy Correctly";

solution = "Set the basic policy package to the targeted policy package:

1. Run the following command to install the target basic policy package:

# yum install selinux-policy-targeted

2. Set the SELINUXTYPE parameter in the /etc/selinux/config file to modify the basic policy package
of the system.

# SELINUXTYPE=targeted

3. Create the .autorelabel file in the root directory to refresh the file label after the system is
restarted.

# touch /.autorelabel

4. Restart the OS.
If an application runs abnormally, you need to configure a proper SELinux policy for the
application.";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# sestatus | grep "Loaded policy name" | awk \'{print \\$4}\'';

expected_value = 'The output should be equal to "targeted"';

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
# CHECK : Verify command `sestatus | grep 'Loaded policy name' | awk '{print \$4}`
# ------------------------------------------------------------------
step_cmd = 'sestatus | grep "Loaded policy name" | awk \'{print \\$4}\'';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value == 'targeted'){
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