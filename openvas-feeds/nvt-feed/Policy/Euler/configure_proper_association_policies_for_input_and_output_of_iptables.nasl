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
  script_oid("1.3.6.1.4.1.25623.1.0.130360");
  script_version("2025-09-22T07:08:28+0000");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure Proper Association Policies for INPUT and OUTPUT of iptables");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.10 Configure Proper Association Policies for INPUT and OUTPUT of iptables (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.10 Configure Proper Association Policies for INPUT and OUTPUT of iptables (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.10 Configure Proper Association Policies for INPUT and OUTPUT of iptables (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.10 Configure Proper Association Policies for INPUT and OUTPUT of iptables (Recommendation)");

  script_tag(name:"summary", value:"Although you can configure protocols, IP addresses, and port
numbers to add policies for packets entering and leaving a server to the INPUT and OUTPUT chains,
it is difficult to configure suitable policies using the sport parameter due to complicated
situations. For example, a client accesses the server through a port, but the server may return a
response packet from another random source port instead of the original port.

In this case, you need to configure policies by associating connections. If an outgoing packet
belongs to an existing network connection, the packet is directly permitted. If a received packet
belongs to an existing network connection, the packet is also directly permitted. The existing
connections must be filtered and checked by other policies. Otherwise, the connections cannot be
established.

If you configure policies not by associating connections, you need to analyze all possible chains
and configure corresponding policies. If the configuration is too loose, security risks may occur.
Otherwise, services may be interrupted.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure Proper Association Policies for INPUT and OUTPUT of iptables";

solution = "Configure TCP, UDP, and ICMP policies for the OUTPUT chain to allow packets from all
new and established connections to be sent out. Configure TCP, UDP, and ICMP policies for the INPUT
chain to allow packets from established connections to be received.

# iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
# iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
# iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
# iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
# iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
# iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

Run the following command to make the configured policies take effect permanently:

# service iptables save
iptables: Saving firewall rules to /etc/sysconfig/iptables: [  OK  ]

Run the following commands to configure the IPv6-based policies:

# ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
# ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
# ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
# ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
# ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
# ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

Run the following command to make the configured policies take effect permanently:

# service ip6tables save
ip6tables: Saving firewall rules to /etc/sysconfig/ip6tables: [  OK  ]";

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# iptables-save

2. Run the command in the terminal:
# ip6tables-save';

expected_value = '1. The output should contain "-A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT" and contain "-A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT" and contain "-A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT" and contain "-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT" and contain "-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT" and contain "-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT"
2. The output should contain "-A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT" and contain "-A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT" and contain "-A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT" and contain "-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT" and contain "-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT" and contain "-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT"';

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
# CHECK 1 :  Verify command `iptables-save`
# ------------------------------------------------------------------

step_cmd_check_1 = 'iptables-save';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(strstr(step_res_check_1, '-A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT') && strstr(step_res_check_1, '-A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT') && strstr(step_res_check_1, '-A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT') && strstr(step_res_check_1, '-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT') && strstr(step_res_check_1, '-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT') && strstr(step_res_check_1, '-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT')){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify command `ip6tables-save`
# ------------------------------------------------------------------

step_cmd_check_2 = 'ip6tables-save';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(strstr(step_res_check_2, '-A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT') && strstr(step_res_check_2, '-A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT') && strstr(step_res_check_2, '-A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT') && strstr(step_res_check_2, '-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT') && strstr(step_res_check_2, '-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT') && strstr(step_res_check_2, '-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT')){
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
