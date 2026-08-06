# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.134194");
  script_version("2026-08-05T06:26:26+0000");
  script_tag(name:"last_modification", value:"2026-08-05 06:26:26 +0000 (Wed, 05 Aug 2026)");
  script_tag(name:"creation_date", value:"2026-07-29 08:00:09 +0000 (Wed, 29 Jul 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure gpgcheck Is Enabled");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "compliance_os_check.nasl");
  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/hce");
  script_xref(name:"Policy", value:"Huawei Cloud HCE 2.0 Security Configuration Baseline: 1.3.2 Ensure gpgcheck Is Enabled (Required)(Automated)");

  script_tag(name:"summary", value:"GPG signature verification must be enabled globally and must not be disabled by a Yum repository configuration.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure gpgcheck Is Enabled";

solution = "Open the file in which gpgcheck is set to 0, and modify the value to 1.
gpgcheck=1";

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# grep ^gpgcheck /etc/dnf/dnf.conf
2. Run the command in the terminal:
# grep -inEh "^\\s*gpgcheck" /etc/yum.repos.d/* 2>/dev/null | grep -v -x -i ".*gpgcheck=1"';

expected_value = '1. The output should be equal to "gpgcheck=1"
2. The output should be empty';

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
# CHECK 1 : Check gpgcheck in /etc/dnf/dnf.conf
# ------------------------------------------------------------------

step_cmd_check_1 = "grep ^gpgcheck /etc/dnf/dnf.conf 2>/dev/null";
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += "1. " + step_res_check_1 + "\n";
check_result_1 = FALSE;

if(step_res_check_1){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 : Check gpgcheck in /etc/yum.repos.d
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep -irE "^gpgcheck[ ]*=[ ]*0" /etc/yum.repos.d/ 2>/dev/null';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += "2. " + step_res_check_2 + "\n";
check_result_2 = FALSE;

if(!step_res_check_2){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------

if(eregmatch(string: actual_value, pattern:"(No such file or directory|Permission denied|Command not found|Segmentation fault|syntax error)", icase: TRUE)){
  compliant = "incomplete";
  comment = "Something went wrong during the audit check. Please try again.";
}else if(check_result_1 && check_result_2){
  compliant = "yes";
  comment = "All checks passed";
}else{
  compliant = "no";
  comment = "One or more checks failed";
}

# ------------------------------------------------------------------
# REPORT
# ------------------------------------------------------------------

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
