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
  script_oid("1.3.6.1.4.1.25623.1.0.130302");
  script_version("2025-08-22T15:40:55+0000");
  script_tag(name:"last_modification", value:"2025-08-22 15:40:55 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure the Rotate Policy in rsyslog");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.7 Configure the Rotate Policy in rsyslog (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.7 Configure the Rotate Policy in rsyslog (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.7 Configure the Rotate Policy in rsyslog (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.7 Configure the Rotate Policy in rsyslog (Requirement)");

  script_tag(name:"summary", value:"rsyslog collects logs from the system and records them in
files. logrotate copies and compresses log files periodically and quantitatively to ensure that log
files do not occupy too many drive resources or even cannot be maintained.
If the rotate policy is not configured for log files, they will accumulate until the drive
partition space runs out. As a result, logging can be affected, or worse still, the system and
services may fail.
In openEuler, the rotate policy of rsyslog is configured in /etc/logrotate.d/rsyslog by default as
follows:

1. rotate log files:
/var/log/cron
/var/log/maillog
/var/log/messages
/var/log/secure
/var/log/spooler

2. The maximum retention period of log files is 365 days.

3. A maximum of 30 log files can be retained.

4. Log files are compressed and retained.

5. A log file is rotated when its size reaches 4 MB.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure the Rotate Policy in rsyslog";

solution = 'Create a configuration file, for example, /etc/logrotate.d/rsyslog, in the
/etc/logrotate.d directory. Check and add the following configurations. <log file paths> indicates
the rsyslog log output path configured in the /etc/rsyslog.conf file. The two paths must be the
same:

# vim /etc/logrotate.d/rsyslog
<log file paths>
{
    maxage <days>
    rotate <files counts>
    notifempty
    compress
    copytruncate
    missingok
    size +<numeric value in kilobyte>k
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /var/run/rsyslogd.pid 2> /dev/null` 2> /dev/null <pipe><pipe> true
    endscript
}';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# grep -E "/var/log/(cron|maillog|messages|secure|spooler)" /etc/logrotate.d/rsyslog

2. Run the command in the terminal:
# grep -E "maxage[[:space:]]+365" /etc/logrotate.d/rsyslog

3. Run the command in the terminal:
# grep -E "rotate[[:space:]]+30" /etc/logrotate.d/rsyslog

4. Run the command in the terminal:
# grep -E "compress" /etc/logrotate.d/rsyslog

5. Run the command in the terminal:
# grep -E "size[[:space:]]+\\+4096k" /etc/logrotate.d/rsyslog';

expected_value = '1. The output should contain "/var/log/cron" and contain "/var/log/maillog" and contain "/var/log/messages" and contain "/var/log/secure" and contain "/var/log/spooler"
2. The output should contain "maxage 365"
3. The output should contain "rotate 30"
4. The output should contain "compress"
5. The output should contain "size +4096k"';

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

overall_pass = FALSE;
actual_value = "";

# ------------------------------------------------------------------
# CHECK 1 :  Verify that the correct log paths are defined:
# ------------------------------------------------------------------

step_cmd_check_1 = 'grep -E "/var/log/(cron|maillog|messages|secure|spooler)" /etc/logrotate.d/rsyslog';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(strstr(step_res_check_1, '/var/log/cron') && strstr(step_res_check_1, '/var/log/maillog') && strstr(step_res_check_1, '/var/log/messages') && strstr(step_res_check_1, '/var/log/secure') && strstr(step_res_check_1, '/var/log/spooler')){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify that maxage is set to 365
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep -E "maxage[[:space:]]+365" /etc/logrotate.d/rsyslog';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(strstr(step_res_check_2, 'maxage 365')){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 3 :  Verify that rotate is set to 30
# ------------------------------------------------------------------

step_cmd_check_3 = 'grep -E "rotate[[:space:]]+30" /etc/logrotate.d/rsyslog';
step_res_check_3 = ssh_cmd(socket:sock, cmd:step_cmd_check_3, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '3. ' + step_res_check_3 + '\n';
check_result_3 = FALSE;

if(strstr(step_res_check_3, 'rotate 30')){
  check_result_3 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 4 :  Verify that compress is enabled
# ------------------------------------------------------------------

step_cmd_check_4 = 'grep -E "compress" /etc/logrotate.d/rsyslog';
step_res_check_4 = ssh_cmd(socket:sock, cmd:step_cmd_check_4, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '4. ' + step_res_check_4 + '\n';
check_result_4 = FALSE;

if(strstr(step_res_check_4, 'compress')){
  check_result_4 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 5 :  Verify that log file size threshold is 4 MB
# ------------------------------------------------------------------

step_cmd_check_5 = 'grep -E "size[[:space:]]+\\+4096k" /etc/logrotate.d/rsyslog';
step_res_check_5 = ssh_cmd(socket:sock, cmd:step_cmd_check_5, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '5. ' + step_res_check_5 + '\n';
check_result_5 = FALSE;

if(strstr(step_res_check_5, 'size +4096k')){
  check_result_5 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------
if(check_result_1 && check_result_2 && check_result_3 && check_result_4 && check_result_5){
  overall_pass = TRUE;
}

if(overall_pass){
  compliant = "yes";
  comment = "All checks passed";
}else{
  compliant = "no";
  comment = "One or more checks failed";
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