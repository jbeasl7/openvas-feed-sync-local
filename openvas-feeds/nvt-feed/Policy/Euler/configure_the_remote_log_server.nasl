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
  script_oid("1.3.6.1.4.1.25623.1.0.130298");
  script_version("2025-08-28T05:39:05+0000");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure the Remote Log Server");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.8 Configure the Remote Log Server (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.8 Configure the Remote Log Server (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.8 Configure the Remote Log Server (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.8 Configure the Remote Log Server (Recommendation)");

  script_tag(name:"summary", value:"rsyslog can send local logs to a remote log server for unified
storage. This facilitates centralized log management, prevents local logs from occupying too much
drive space and being tampered with.

If remote log storage is not configured, rsyslog logs are stored in local files. As far as the
administrator correctly configures the log storage paths and rotate-policy parameters, the system
and services are not affected. If remote log storage is configured, log transmission security must
be ensured. For example, logs must be encrypted before transmission or be transmitted through a
secure encryption channel (TCP + TLS1.2 or later).

By default, remote log storage is not configured in openEuler. You are advised to configure it
based on the actual service scenario.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure the Remote Log Server";

solution = "In the /etc/rsyslog.d/ directory, create a configuration file with the file name
extension conf, for example, server.conf, and add the following configurations in the file. In the
command, the symbol . indicates that all logs are displayed on the server. *.* means <log
type>._<log level>_. For example, mail.info indicates that only mail logs with level info are
displayed on the server. @ indicates that the UDP protocol is used. @@ indicates that the TCP
protocol is used.

# vim /etc/rsyslog.d/server.conf
*.* @@<remote IP>:<remote port>
# For IPv6, add the following configuration:
*.* @@[<remove IPv6>%<interface name>]:<remote port>

Run the following command to restart the service for the configuration to take effect:

# systemctl restart rsyslog.service";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -HirE "^.*@*:[0-9]+$" /etc/rsyslog.d/ 2>/dev/null';

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
# CHECK : Verify command `grep -HirE "^.*@*:[0-9]+$" /etc/rsyslog.d/ 2>/dev/null`
# ------------------------------------------------------------------
step_cmd = 'grep -HirE "^.*@*:[0-9]+$" /etc/rsyslog.d/ 2>/dev/null';
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