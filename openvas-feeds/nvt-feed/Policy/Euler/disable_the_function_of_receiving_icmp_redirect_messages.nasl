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
  script_oid("1.3.6.1.4.1.25623.1.0.130343");
  script_version("2025-08-22T15:40:55+0000");
  script_tag(name:"last_modification", value:"2025-08-22 15:40:55 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Disable the Function of Receiving ICMP Redirect Messages");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.7 Disable the Function of Receiving ICMP Redirect Messages (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.7 Disable the Function of Receiving ICMP Redirect Messages (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.7 Disable the Function of Receiving ICMP Redirect Messages (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.7 Disable the Function of Receiving ICMP Redirect Messages (Requirement)");

  script_tag(name:"summary", value:"ICMP redirect messages transmit routing information and notify
hosts of a better path through which the hosts send data packets. This is a method for allowing an
external routing device to update a system routing table. After both
net.ipv4.conf.all.accept_redirects and net.ipv6.conf.all.accept_redirects are set to 0, the system
denies all ICMP redirect messages. If net.ipv4.conf.all.secure_redirects and
net.ipv4.conf.default.send_redirects are set to 0, the system does not receive ICMP redirect
messages from the gateway. This configuration item is unavailable in IPv6 scenarios.

Attackers can exploit forged ICMP redirect messages to maliciously change the system routing table
and send data packets to incorrect networks to obtain sensitive data.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Disable the Function of Receiving ICMP Redirect Messages";

solution = 'Run the following commands to disable the function of receiving ICMP redirect messages:

# sysctl -w net.ipv4.conf.all.accept_redirects=0
# sysctl -w net.ipv6.conf.all.accept_redirects=0
# sysctl -w net.ipv4.conf.all.secure_redirects=0
# sysctl -w net.ipv4.conf.default.secure_redirects=0

Open the /etc/sysctl.conf file and add or modify the following configurations:

net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# sysctl net.ipv4.conf.all.accept_redirects && sysctl net.ipv6.conf.all.accept_redirects && sysctl net.ipv4.conf.all.secure_redirects && sysctl net.ipv4.conf.default.secure_redirects

2. Run the command in the terminal:
# grep -Eh \'net.ipv4.conf.all.accept_redirects\' /etc/sysctl.conf /etc/sysctl.d/

3. Run the command in the terminal:
# grep -Eh \'net.ipv6.conf.all.accept_redirects\' /etc/sysctl.conf /etc/sysctl.d/*

4. Run the command in the terminal:
# grep -Eh \'net.ipv4.conf.all.secure_redirects\' /etc/sysctl.conf /etc/sysctl.d/*

5. Run the command in the terminal:
# grep -Eh \'net.ipv4.conf.default.secure_redirects\' /etc/sysctl.conf /etc/sysctl.d/*';

expected_value = '1. The output should match the pattern "net.ipv4.conf.all.accept_redirects = 0\\\\s*net.ipv6.conf.all.accept_redirects = 0\\\\s*net.ipv4.conf.all.secure_redirects = 0\\\\s*net.ipv4.conf.default.secure_redirects = 0\\\\s*"
2. The output should contain "net.ipv4.conf.all.accept_redirects=0"
3. The output should contain "net.ipv6.conf.all.accept_redirects=0"
4. The output should contain "net.ipv4.conf.all.secure_redirects=0"
5. The output should contain "net.ipv4.conf.default.secure_redirects=0"';

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
# CHECK 1 :  Check sysctl
# ------------------------------------------------------------------

step_cmd_check_1 = 'sysctl net.ipv4.conf.all.accept_redirects && sysctl net.ipv6.conf.all.accept_redirects && sysctl net.ipv4.conf.all.secure_redirects && sysctl net.ipv4.conf.default.secure_redirects';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 =~ 'net.ipv4.conf.all.accept_redirects = 0\\s*net.ipv6.conf.all.accept_redirects = 0\\s*net.ipv4.conf.all.secure_redirects = 0\\s*net.ipv4.conf.default.secure_redirects = 0\\s*'){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify command  `grep -Eh \'net.ipv4.conf.all.accept_redirects\' /etc/sysctl.conf /etc/sysctl.d/*`
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep -Eh \'net.ipv4.conf.all.accept_redirects\' /etc/sysctl.conf /etc/sysctl.d/';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(strstr(step_res_check_2, 'net.ipv4.conf.all.accept_redirects=0')){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 3 :  Verify command `grep -Eh \'net.ipv6.conf.all.accept_redirects\' /etc/sysctl.conf /etc/sysctl.d/*`
# ------------------------------------------------------------------

step_cmd_check_3 = 'grep -Eh \'net.ipv6.conf.all.accept_redirects\' /etc/sysctl.conf /etc/sysctl.d/*';
step_res_check_3 = ssh_cmd(socket:sock, cmd:step_cmd_check_3, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '3. ' + step_res_check_3 + '\n';
check_result_3 = FALSE;

if(strstr(step_res_check_3, 'net.ipv6.conf.all.accept_redirects=0')){
  check_result_3 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 4 :  Verify command `grep -Eh \'net.ipv4.conf.all.secure_redirects\' /etc/sysctl.conf /etc/sysctl.d/*`
# ------------------------------------------------------------------

step_cmd_check_4 = 'grep -Eh \'net.ipv4.conf.all.secure_redirects\' /etc/sysctl.conf /etc/sysctl.d/*';
step_res_check_4 = ssh_cmd(socket:sock, cmd:step_cmd_check_4, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '4. ' + step_res_check_4 + '\n';
check_result_4 = FALSE;

if(strstr(step_res_check_4, 'net.ipv4.conf.all.secure_redirects=0')){
  check_result_4 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 5 :  Verify command `grep -Eh \'net.ipv4.conf.default.secure_redirects\' /etc/sysctl.conf /etc/sysctl.d/*`
# ------------------------------------------------------------------

step_cmd_check_5 = 'grep -Eh \'net.ipv4.conf.default.secure_redirects\' /etc/sysctl.conf /etc/sysctl.d/*';
step_res_check_5 = ssh_cmd(socket:sock, cmd:step_cmd_check_5, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '5. ' + step_res_check_5 + '\n';
check_result_5 = FALSE;

if(strstr(step_res_check_5, 'net.ipv4.conf.default.secure_redirects=0')){
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