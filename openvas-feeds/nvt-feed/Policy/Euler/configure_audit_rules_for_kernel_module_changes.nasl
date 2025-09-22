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
  script_oid("1.3.6.1.4.1.25623.1.0.130287");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure Audit Rules for Kernel Module Changes");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.6 Configure Audit Rules for Kernel Module Changes (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.6 Configure Audit Rules for Kernel Module Changes (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.6 Configure Audit Rules for Kernel Module Changes (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.6 Configure Audit Rules for Kernel Module Changes (Recommendation)");

  script_tag(name:"summary", value:"Generally, for deployed services, the loaded kernel modules do
not change. Therefore, changes in loaded kernel modules may indicate attacks. You are advised to
audit and monitor kernel module changes for future tracing.

By default, audit rules for kernel module changes are not configured in openEuler. You are advised
to configure rules based on the actual service scenario.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure Audit Rules for Kernel Module Changes";

solution = "For a 32-bit system, create a rule file, for example, module.rules, in the
/etc/audit/rules.d/ directory and add audit rules to the file.

# vim /etc/audit/rules.d/module.rules
-w /sbin/insmod -p x -k <rules name>
-w /sbin/rmmod -p x -k <rules name>
-w /sbin/modprobe -p x -k <rules name>
-a always,exit -F arch=b32 -S init_module -S delete_module -k <rules name>

For a 64-bit system, add content related to arch=b64:

-a always,exit -F arch=b64 -S init_module -S delete_module -k <rules name>

To ensure compatibility, the configuration related to arch=b32 in the 64-bit system must be
retained.

Restart the auditd service for the rules to take effect.

# service auditd restart
Stopping logging: [  OK  ]
Redirecting start to /bin/systemctl start auditd.service";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# auditctl -l 2>/dev/null | grep -iE "((-w\\s*/\\S+(/\\S+)?)(insmod|rmmod|modprobe)|(-S\\s*)(init_module,delete_module|delete_module,init_module))"';

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
# CHECK : Check "insmod|rmmod|modprobe|init_module|delete_module" in auditctl
# ------------------------------------------------------------------

step_cmd = 'auditctl -l 2>/dev/null | grep -iE "((-w\\s*/\\S+(/\\S+)?)(insmod|rmmod|modprobe)|(-S\\s*)(init_module,delete_module|delete_module,init_module))"';
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

