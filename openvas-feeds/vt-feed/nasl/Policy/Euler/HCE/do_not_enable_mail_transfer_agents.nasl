# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.134056");
  script_version("2026-08-05T06:26:26+0000");
  script_tag(name:"last_modification", value:"2026-08-05 06:26:26 +0000 (Wed, 05 Aug 2026)");
  script_tag(name:"creation_date", value:"2026-07-17 00:00:00 +0000 (Fri, 17 Jul 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Enable Mail Transfer Agents");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "compliance_os_check.nasl");
  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/hce");
  script_xref(name:"Policy", value:"Huawei Cloud HCE 2.0 Security Configuration Baseline: 1.2.24 Do Not Enable Mail Transfer Agents (Required)(Automated)");

  script_tag(name:"summary", value:"Mail Transfer Agents (MTAs), such as sendmail and Postfix, are
  used to listen for incoming emails and transfer the emails to the corresponding users or mail
  servers. MTAs are complex, and many have a long history of security vulnerabilities. If the
  system is not intended to be used as a mail server, you are advised to disable MTAs. By default,
  MTAs are disabled in HCE.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Enable Mail Transfer Agents";

solution = "Run the following commands to disable sendmail and Postfix:
# systemctl --now disable postfix
# systemctl --now disable sendmail
# systemctl --now stop postfix
# systemctl --now stop sendmail";

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# systemctl is-enabled postfix

2. Run the command in the terminal:
# systemctl is-enabled sendmail';

expected_value = '1. The output should be equal to "disabled" or "not-found", or contain "Failed to get unit file state".
2. The output should be equal to "disabled" or "not-found", or contain "Failed to get unit file state".';

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
# CHECK 1 : Verify that the Postfix service is disabled
# ------------------------------------------------------------------

step_cmd_check_1 = 'systemctl is-enabled postfix';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 == 'disabled' || step_res_check_1 == 'not-found' || strstr(step_res_check_1, 'Failed to get unit file state')){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 : Verify that the Sendmail service is disabled
# ------------------------------------------------------------------

step_cmd_check_2 = 'systemctl is-enabled sendmail';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(step_res_check_2 == 'disabled' || step_res_check_2 == 'not-found' || strstr(step_res_check_2, 'Failed to get unit file state')){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------

if(eregmatch(string: actual_value, pattern:"(No such file or directory|Permission denied|Command not found|Segmentation fault|service not found|is not running|syntax error near unexpected token|syntax error: unexpected end of file)", icase: TRUE)){
  compliant = "incomplete";
  comment = "Something went wrong during the audit check. Please try again.";
}else if(check_result_1 && check_result_2){
  compliant = "yes";
  comment = "Both Postfix and Sendmail are disabled or not installed.";
}else{
  compliant = "no";
  comment = "At least one mail transfer agent is enabled.";
}

target = get_kb_item("policy/ssh/login/os-release");
comment = "Target: " + target + "\n" + comment;

report_audit(action: action,
             actual_value: actual_value,
             expected_value: expected_value,
             is_compliant: compliant,
             solution: solution,
             check_type: check_type,
             title: title,
             comment: comment);

exit(0);

