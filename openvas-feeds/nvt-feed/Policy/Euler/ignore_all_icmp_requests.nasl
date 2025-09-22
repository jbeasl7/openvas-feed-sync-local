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
  script_oid("1.3.6.1.4.1.25623.1.0.130333");
  script_version("2025-08-28T05:39:05+0000");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ignore All ICMP Requests");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.9 Ignore All ICMP Requests (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.9 Ignore All ICMP Requests (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.9 Ignore All ICMP Requests (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.9 Ignore All ICMP Requests (Recommendation)");

  script_tag(name:"summary", value:"Ignoring all ICMP requests to prohibit external systems from
running the ping command to detect the system location.

Attackers can detect the URL of the system based on the returned result of the ping command.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ignore All ICMP Requests";

solution = 'Run the following command to ignore all ICMP requests:

# sysctl -w net.ipv4.icmp_echo_ignore_all=1

Open the /etc/sysctl.conf file and add or modify the following configuration:

net.ipv4.icmp_echo_ignore_all=1';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# sysctl net.ipv4.icmp_echo_ignore_all

2. Run the command in the terminal:
# grep -E "^\\s*net.ipv4.icmp_echo_ignore_all" /etc/sysctl.conf /etc/sysctl.d/*';

expected_value = '1. The output should be equal to "net.ipv4.icmp_echo_ignore_all = 1"
2. The output should not be empty and not contain "net.ipv4.icmp_echo_ignore_all=0"';

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
# CHECK 1 :  Verify command `sysctl net.ipv4.icmp_echo_ignore_all`
# ------------------------------------------------------------------

step_cmd_check_1 = 'sysctl net.ipv4.icmp_echo_ignore_all';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 == 'net.ipv4.icmp_echo_ignore_all = 1'){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify command `grep -E "^\\s*net.ipv4.icmp_echo_ignore_all" /etc/sysctl.conf /etc/sysctl.d/*`
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep -E "^\\s*net.ipv4.icmp_echo_ignore_all" /etc/sysctl.conf /etc/sysctl.d/*';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(step_res_check_2 && !strstr(step_res_check_2, 'net.ipv4.icmp_echo_ignore_all=0')){
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