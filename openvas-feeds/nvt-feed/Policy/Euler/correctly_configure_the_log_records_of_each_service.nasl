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
  script_oid("1.3.6.1.4.1.25623.1.0.130301");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Correctly Configure the Log Records of Each Service");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.5 Correctly Configure the Log Records of Each Service (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.5 Correctly Configure the Log Records of Each Service (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.5 Correctly Configure the Log Records of Each Service (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.5 Correctly Configure the Log Records of Each Service (Recommendation)");

  script_tag(name:"summary", value:"Logs should be configured so that important system behaviors
and security-related information are recorded by rsyslog. The configuration files /etc/rsyslog.conf
and /etc/rsyslog.d/*.conf specify the rules for logging and the files for recording specific types
of logs.

If logging is not configured, system behaviors cannot be recorded. As a result, faults cannot be
located and audited.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Correctly Configure the Log Records of Each Service";

solution = "Configure proper logging rules in /etc/rsyslog.conf and /etc/rsyslog.d/*.conf. The
following uses /etc/rsyslog.conf as an example:

# vim /etc/rsyslog.conf
/etc/rsyslog.conf:*.info<semicolon>mail.none<semicolon>authpriv.none<semicolon>cron.none
/var/log/messages
/etc/rsyslog.conf:authpriv.*                                 /var/log/secure
/etc/rsyslog.conf:mail.*                                    /var/log/maillog
/etc/rsyslog.conf:cron.*                                    /var/log/cron
/etc/rsyslog.conf:uucp,news.crit                             /var/log/spooler
/etc/rsyslog.conf:local7.*                                  /var/log/boot.log

The system administrator needs to properly configure logging rules as required. Take a mail log as
an example. The symbol * indicates logs of all levels, and /var/log/maillog indicates that
mail-related logs are recorded in this file. For details about the log configuration rules, see the
standard of rsyslog.

Run the following command to restart the service for the configuration to take effect:

# systemctl restart rsyslog.service";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -vE "^\\s*#" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -E "/var/log[^ ]*$"';

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
# CHECK : Verify command `grep -vE "^\s*#" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -E "/var/log[^ ]*$"`
# ------------------------------------------------------------------

step_cmd = 'grep -vE "^\\s*#" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -E "/var/log[^ ]*$"';
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
