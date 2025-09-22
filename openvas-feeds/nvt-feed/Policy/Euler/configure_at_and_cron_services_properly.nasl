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
  script_oid("1.3.6.1.4.1.25623.1.0.130353");
  script_version("2025-08-22T15:40:55+0000");
  script_tag(name:"last_modification", value:"2025-08-22 15:40:55 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure at and cron Services Properly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.4 Scheduled Tasks: 3.4.3 Configure at and cron Services Properly (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.4 Scheduled Tasks: 3.4.3 Configure at and cron Services Properly (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.4 Scheduled Tasks: 3.4.3 Configure at and cron Services Properly (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.4 Scheduled Tasks: 3.4.3 Configure at and cron Services Properly (Requirement)");

  script_tag(name:"summary", value:"The at service is used to execute simple tasks once, and the
cron service is used to execute periodic and scheduled tasks. In the cron command, the
/etc/cron.deny file is the blocklist configuration file, and the /etc/cron.allow file is the
allowlist configuration file, which is absent by default. When the allowlist is enabled, the
blocklist becomes invalid. Only the root user and allowlisted users can use the cron command.

In the blocklist mechanism that manages scheduled cron tasks, you may forget to blocklist a newly
added user, thereby increasing the potential attack surface of the system. If the owner of the
cron-related configuration file is not the root user or the group and other users are allowed to
access the file, users other than the system administrator may configure the cron, which brings
system security risks. If the at and cron services do not need to be enabled, you do not need to
check this configuration option.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure at and cron Services Properly";

solution = '1. If the cron service is not enabled, run the following command to enable it:

# systemctl --now enable crond

2. Run the following commands to set the UID/GID and permissions for the /etc/crontab file and the
/etc/cron.hourly, /etc/cron.daily, /etc/cron.weekly, /etc/cron.monthly, and /etc/cron.d directories:

# chown root:root /etc/crontab
# chmod og-rwx /etc/crontab

3. Run the following commands to delete the /etc/cron.deny and /etc/at.deny files, create the
/etc/cron.allow and /etc/at.allow files, and set correct permissions on the files:

# rm /etc/cron.deny /etc/at.deny
# touch /etc/cron.allow /etc/at.allow
# chmod og-rwx /etc/cron.allow
# chmod og-rwx /etc/at.allow
# chown root:root /etc/cron.allow
# chown root:root /etc/at.allow';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# systemctl is-enabled "crond"

2. Run the command in the terminal:
# systemctl is-active "crond"

3. Run the command in the terminal:
# stat -c "%a %U %G %n" "/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/etc/cron.d" 2>/dev/null | grep \'^700 root root \'

4. Run the command in the terminal:
# stat -c "%a %U %G %n" "/etc/crontab"

5. Run the command in the terminal:
# ls "/etc/cron.deny" "/etc/at.deny" 2>/dev/null

6. Run the command in the terminal:
# stat -c "%a %U %G %n" "/etc/cron.allow" "/etc/at.allow"  2>/dev/null';

expected_value = '1. The output should be equal to "enabled"
2. The output should be equal to "active"
3. The output should contain "700 root root /etc/cron.hourly" and contain "700 root root /etc/cron.daily" and contain "700 root root /etc/cron.weekly" and contain "700 root root /etc/cron.monthly" and contain "700 root root /etc/cron.d"
4. The output should contain "600 root root /etc/crontab"
5. The output should be empty
6. The output should contain "600 root root /etc/cron.allow" and contain "600 root root /etc/at.allow"';

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
# CHECK 1 :  Check crond service is enabled or not
# ------------------------------------------------------------------

step_cmd_check_1 = 'systemctl is-enabled "crond"';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 == 'enabled'){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check cron service is active or not
# ------------------------------------------------------------------

step_cmd_check_2 = 'systemctl is-active "crond"';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(step_res_check_2 == 'active'){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 3 :  Check /etc/cron path permissions
# ------------------------------------------------------------------

step_cmd_check_3 = 'stat -c "%a %U %G %n" "/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/etc/cron.d" 2>/dev/null | grep \'^700 root root \'';
step_res_check_3 = ssh_cmd(socket:sock, cmd:step_cmd_check_3, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '3. ' + step_res_check_3 + '\n';
check_result_3 = FALSE;

if(strstr(step_res_check_3, '700 root root /etc/cron.hourly') && strstr(step_res_check_3, '700 root root /etc/cron.daily') && strstr(step_res_check_3, '700 root root /etc/cron.weekly') && strstr(step_res_check_3, '700 root root /etc/cron.monthly') && strstr(step_res_check_3, '700 root root /etc/cron.d')){
  check_result_3 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 4 :  Check /etc/crontab permission
# ------------------------------------------------------------------

step_cmd_check_4 = 'stat -c "%a %U %G %n" "/etc/crontab"';
step_res_check_4 = ssh_cmd(socket:sock, cmd:step_cmd_check_4, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '4. ' + step_res_check_4 + '\n';
check_result_4 = FALSE;

if(strstr(step_res_check_4, '600 root root /etc/crontab')){
  check_result_4 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 5 :  Check blocklist is exist
# ------------------------------------------------------------------

step_cmd_check_5 = 'ls "/etc/cron.deny" "/etc/at.deny" 2>/dev/null';
step_res_check_5 = ssh_cmd(socket:sock, cmd:step_cmd_check_5, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '5. ' + step_res_check_5 + '\n';
check_result_5 = FALSE;

if(!step_res_check_5){
  check_result_5 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 6 :  Check etc/cron.allow permission
# ------------------------------------------------------------------

step_cmd_check_6 = 'stat -c "%a %U %G %n" "/etc/cron.allow" "/etc/at.allow"  2>/dev/null';
step_res_check_6 = ssh_cmd(socket:sock, cmd:step_cmd_check_6, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '6. ' + step_res_check_6 + '\n';
check_result_6 = FALSE;

if(strstr(step_res_check_6, '600 root root /etc/cron.allow') && strstr(step_res_check_6, '600 root root /etc/at.allow')){
  check_result_6 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------
if(check_result_1 && check_result_2 && check_result_3 && check_result_4 && check_result_5 && check_result_6){
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