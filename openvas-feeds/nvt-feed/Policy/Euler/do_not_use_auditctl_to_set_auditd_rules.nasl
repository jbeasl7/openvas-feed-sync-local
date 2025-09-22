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
  script_oid("1.3.6.1.4.1.25623.1.0.130286");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Use auditctl to Set auditd Rules");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.10 Do Not Use auditctl to Set auditd Rules (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.10 Do Not Use auditctl to Set auditd Rules (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.10 Do Not Use auditctl to Set auditd Rules (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.10 Do Not Use auditctl to Set auditd Rules (Recommendation)");

  script_tag(name:"summary", value:"auditd service rules can be configured using either rule files
in the /etc/audit/rules.d/ directory (applied after server restart) or the auditctl command for
immediate effect. The permission of the /etc/audit/rules.d/ directory is 750, while that of the
auditctl command is 755. Therefore, prohibiting the auditctl command from modifying auditd service
rules prevents unprivileged attackers from modifying rules through commands to launch immediate
attacks, reducing the attack surface.

By default, using auditctl to modify auditd service rules is not prohibited in openEuler. You are
advised to disable configuration of auditd service rules through auditctl based on the service
scenario.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Use auditctl to Set auditd Rules";

solution = "Create a rule file with any name with the suffix `.rules` in the /etc/audit/rules.d/
directory and add -e 2 to the file.

# vim /etc/audit/rules.d/immutable.rules
-e 2

Restart the auditd service for the rules to take effect.

# service auditd restart
Stopping logging: [  OK  ]
Redirecting start to /bin/systemctl start auditd.service";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep "-e 2" /etc/audit/rules.d/*.rules';

expected_value = 'The output should match the pattern "\\/etc\\/audit\\/rules\\.d\\/\\w*.rules:\\s*-e\\s*2"';

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
# CHECK : Verify command `grep "-e 2" /etc/audit/rules.d/*.rules`
# ------------------------------------------------------------------

step_cmd = 'grep "-e 2" /etc/audit/rules.d/*.rules';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value =~ '\\/etc\\/audit\\/rules\\.d\\/\\w*.rules:\\s*-e\\s*2'){
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