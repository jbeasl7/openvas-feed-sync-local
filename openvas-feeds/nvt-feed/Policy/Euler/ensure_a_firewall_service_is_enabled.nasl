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
  script_oid("1.3.6.1.4.1.25623.1.0.130358");
  script_version("2025-08-22T15:40:55+0000");
  script_tag(name:"last_modification", value:"2025-08-22 15:40:55 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure a Firewall Service is Enabled");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.1 Ensure a Firewall Service is Enabled (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.1 Ensure a Firewall Service is Enabled (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.1 Ensure a Firewall Service is Enabled (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.1 Ensure a Firewall Service is Enabled (Recommendation)");

  script_tag(name:"summary", value:"A firewall is a fundamental security control that enforces
mandatory access between networks or systems. Without a firewall, systems are exposed to
unauthorized access, data theft, tampering, bandwidth abuse, and malicious traffic.

Linux commonly provides three firewall services:

firewalld (default in openEuler)

iptables (legacy, supports IPv4 and IPv6 chains)

nftables (modern replacement for iptables, extensible for new protocols)

You are advised to enable only one of these services at a time. Enabling multiple may cause rule
conflicts and service disruptions. If no firewall service is enabled, the system may be vulnerable
to attacks.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure a Firewall Service is Enabled";

solution = 'Enable one firewall service and disable the others:

To enable firewalld (recommended default):

# service firewalld start
# systemctl enable firewalld
# service iptables stop
# systemctl disable iptables# service nftables stop
# systemctl disable nftables

To enable iptables (IPv4/IPv6):

# service iptables start
# systemctl enable iptables
# service ip6tables start
# systemctl enable ip6tables
# service firewalld stop
# systemctl disable firewalld
# service nftables stop
# systemctl disable nftables

To enable nftables:
# service nftables start
# systemctl enable nftables
# service firewalld stop
# systemctl disable firewalld
# service iptables stop
# systemctl disable iptables';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# systemctl is-active firewalld && systemctl is-enabled firewalld

2. Run the command in the terminal:
# systemctl is-active iptables && systemctl is-enabled iptables

3. Run the command in the terminal:
# systemctl is-active nftables && systemctl is-enabled nftables';

expected_value = '1. The output should contain "active" and contain "enabled"
2. The output should contain "active" and contain "enabled"
3. The output should contain "active" and contain "enabled"';

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
# CHECK 1 :  Verify that the firewalld service is active and enabled
# ------------------------------------------------------------------

step_cmd_check_1 = 'systemctl is-active firewalld && systemctl is-enabled firewalld';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(strstr(step_res_check_1, 'active') && strstr(step_res_check_1, 'enabled')){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify that the iptables service is  active and enabled
# ------------------------------------------------------------------

step_cmd_check_2 = 'systemctl is-active iptables && systemctl is-enabled iptables';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(strstr(step_res_check_2, 'active') && strstr(step_res_check_2, 'enabled')){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 3 :  Verify that the nftables service is active and enabled
# ------------------------------------------------------------------

step_cmd_check_3 = 'systemctl is-active nftables && systemctl is-enabled nftables';
step_res_check_3 = ssh_cmd(socket:sock, cmd:step_cmd_check_3, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '3. ' + step_res_check_3 + '\n';
check_result_3 = FALSE;

if(strstr(step_res_check_3, 'active') && strstr(step_res_check_3, 'enabled')){
  check_result_3 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------
if(check_result_1 || check_result_2 || check_result_3){
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