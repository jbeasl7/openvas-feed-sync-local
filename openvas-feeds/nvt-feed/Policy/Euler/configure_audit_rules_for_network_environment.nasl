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
  script_oid("1.3.6.1.4.1.25623.1.0.130290");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure Audit Rules for Network Environment");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.17 Configure Audit Rules for Network Environment (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.17 Configure Audit Rules for Network Environment (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.17 Configure Audit Rules for Network Environment (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.17 Configure Audit Rules for Network Environment (Recommendation)");

  script_tag(name:"summary", value:"Attackers may change the system domain name and host name to
launch attacks, such as host spoofing. It is recommended that the user set the audit of system
calls setdomainname and sethostname and the audit of the /etc/hosts file to monitor changes in the
system domain name and host name. You can set the audit of the /etc/issue and /etc/issue.net files
to monitor the changes in the login prompt information.

If related audit is not configured, it is difficult to trace unauthorized modifications.

By default, network environment audit rules are not configured in openEuler. You are advised to
configure rules based on the actual service scenario.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure Audit Rules for Network Environment";

solution = "For a 32-bit system, create a rule file, for example, hostnet.rules, in the
/etc/audit/rules.d/ directory and add audit rules to the file.

# vim /etc/audit/rules.d/hostnet.rules
-a always,exit -F arch=b32 -S setdomainname -S sethostname -k <rules name>
-w /etc/hosts -p wa -k <rules name>
-w /etc/issue -p wa -k <rules name>
-w /etc/issue.net -p wa -k <rules name>

For a 64-bit system, add configuration related to arch=b64:

-a always,exit -F arch=b64 -S setdomainname -S sethostname -k <rules name>

To ensure compatibility, the configuration related to arch=b32 in the 64-bit system must be
retained.

Restart the auditd service for the rules to take effect.

# service auditd restart
Stopping logging: [  OK  ]
Redirecting start to /bin/systemctl start auditd.service";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# auditctl -l 2>/dev/null | grep -iE "((-w\\s*/\\S+(/\\S+)?)(hosts|issue)|(-S\\s*)(setdomainname,sethostname|sethostname,setdomainname))"';

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
# CHECK : Check "setdomainname|sethostname|hosts|issue"" in auditctl
# ------------------------------------------------------------------

step_cmd = 'auditctl -l 2>/dev/null | grep -iE "((-w\\s*/\\S+(/\\S+)?)(hosts|issue)|(-S\\s*)(setdomainname,sethostname|sethostname,setdomainname))"';
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

