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
  script_oid("1.3.6.1.4.1.25623.1.0.130305");
  script_version("2025-08-28T05:39:05+0000");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:18 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Correctly Configure the Default File Permission For rsyslog");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.4 Correctly Configure the Default File Permission For rsyslog (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.4 Correctly Configure the Default File Permission For rsyslog (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.4 Correctly Configure the Default File Permission For rsyslog (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.4 Correctly Configure the Default File Permission For rsyslog (Recommendation)");

  script_tag(name:"summary", value:"Log files record system behaviors. The rsyslog log tool records
logs in specified files. When the specified log file does not exist in the system, rsyslog creates
a log file. The permission of the created log file can be configured in the rsyslog configuration
file. The configuration of the default file permission is to ensure that the created log file has
proper and secure permissions.

If the file permission of a log is excessive, a common user can also read the log, thereby
increasing the risk of log information leakage and tampering. Proper log file permissions can
protect sensitive log data. You are advised to set the log permission to 0600.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Correctly Configure the Default File Permission For rsyslog";

solution = "Modify /etc/rsyslog.conf or /etc/rsyslog.d/*.conf to set proper permissions for
$FileCreateMode:

# vim /etc/rsyslog.d/test.conf
$FileCreateMode 0600

By default, the /etc/rsyslog.conf file contains configurations in the /etc/rsyslog.d/*.conf file.
Therefore, you can configure either of them.

Run the following command to restart the service for the configuration to take effect:

# systemctl restart rsyslog.service";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -h ^\\s*\\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf';

expected_value = 'The output should match the pattern "\\$FileCreateMode 0600"';

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
# CHECK : Verify command `grep -h ^\s*\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf`
# ------------------------------------------------------------------
step_cmd = 'grep -h ^\\s*\\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value =~ '\\$FileCreateMode 0600'){
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