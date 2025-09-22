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
  script_oid("1.3.6.1.4.1.25623.1.0.130306");
  script_version("2025-09-03T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:19 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Disable the Root User from Logging in to the System Using SSH");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.9 Disable the Root User from Logging in to the System Using SSH (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.9 Disable the Root User from Logging in to the System Using SSH (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.9 Disable the Root User from Logging in to the System Using SSH (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.9 Disable the Root User from Logging in to the System Using SSH (Requirement)");

  script_tag(name:"summary", value:"The PermitRootLogin parameter in the SSH configuration file
/etc/ssh/sshd_config specifies whether the root user can log in to the system using SSH. The root
user is not allowed to log in to the system using SSH. System administrators must use their own
user to log in to the system using SSH and run the sudo or su command to escalate to root
privileges. In this way, a clear audit record can be provided in case of a security event. Before
configuring this parameter, ensure that other system administrator users are available. Otherwise,
SSH remote management may fail after the configuration takes effect.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Disable the Root User from Logging in to the System Using SSH";

solution = 'Open the /etc/ssh/sshd_config file, change the value of PermitRootLogin in to no, and
restart the sshd service.

# vim /etc/ssh/sshd_config
PermitRootLogin no
# systemctl restart sshd';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts 2>/dev/null | awk "{print \\$1}")" 2>/dev/null | grep permitrootlogin

2. Run the command in the terminal:
# grep -Ei "^\\s*PermitRootLogin\\s+yes" /etc/ssh/sshd_config 2>/dev/null';

expected_value = '1. The output should not be equal to "permitrootlogin yes"
2. The output should be empty';

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
# CHECK 1 :  Check permitrootlogin value
# ------------------------------------------------------------------

step_cmd_check_1 = 'sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts 2>/dev/null | awk "{print \\$1}")" 2>/dev/null | grep permitrootlogin';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 != 'permitrootlogin yes'){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check permitrootlogin on sshd_config
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep -Ei "^\\s*PermitRootLogin\\s+yes" /etc/ssh/sshd_config 2>/dev/null';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(!step_res_check_2){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------
if(check_result_1 && check_result_2){
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
