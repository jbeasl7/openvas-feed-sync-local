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
  script_oid("1.3.6.1.4.1.25623.1.0.130366");
  script_version("2025-09-22T07:08:28+0000");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure Proper Association Policies for INPUT and OUTPUT of nftables");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_add_preference(name:"Table", type:"entry", value:"test", id:1);
  script_add_preference(name:"Chain Input", type:"entry", value:"input", id:2);
  script_add_preference(name:"Chain Output", type:"entry", value:"output", id:3);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.16 Configure Proper Association Policies for INPUT and OUTPUT of nftables (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.16 Configure Proper Association Policies for INPUT and OUTPUT of nftables (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.16 Configure Proper Association Policies for INPUT and OUTPUT of nftables (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.16 Configure Proper Association Policies for INPUT and OUTPUT of nftables (Recommendation)");

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

table = script_get_preference("Table");
chain_input = script_get_preference("Chain Input");
chain_output = script_get_preference("Chain Output");

title = "Configure Proper Association Policies for INPUT and OUTPUT of nftables";

solution = "Configure TCP, UDP, and ICMP policies for the OUTPUT chain to allow packets from all
new and established connections to be sent out. Configure TCP, UDP, and ICMP policies for the INPUT
chain to allow packets from established connections to be received.

# nft add rule inet test output ip protocol tcp ct state new,related,established accept
# nft add rule inet test output ip protocol udp ct state new,related,established accept
# nft add rule inet test output ip protocol icmp ct state new,related,established accept
# nft add rule inet test input ip protocol tcp ct state established accept
# nft add rule inet test input ip protocol udp ct state established accept
# nft add rule inet test input ip protocol icmp ct state established accept

Save the currently configured policies to the configuration file as follows so that they can be
automatically loaded after the system restarts.

# nft list ruleset > /etc/sysconfig/nftables.conf

Note that saving the configuration file using the preceding method will overwrite the original
configuration. You can also export the current rule to an independent file or compile a new rule in
the original file and load the rule in include mode in the /etc/sysconfig/nftables.conf
configuration file. If you use this method, avoid duplicate rules in multiple include rule files.

# nft list ruleset > /etc/nftables/new_test_rules.nft
# echo <quote>include \\<quote>/etc/nftables/new_test_rules.nft\\<quote><quote> >> /etc/sysconfig/nftables.conf";

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# nft list chain inet '+ table +' '+ chain_input +' 2>/dev/null

2. Run the command in the terminal:
# nft list chain inet '+ table +' '+ chain_output +' 2>/dev/null';

expected_value = '1. The output should contain "ip protocol tcp ct state established accept" and contain "ip protocol udp ct state established accept" and contain "ip protocol icmp ct state established accept"
2. The output should contain "ip protocol tcp ct state established,related,new accept" and contain "ip protocol udp ct state established,related,new accept" and contain "ip protocol icmp ct state established,related,new accept"';

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
# CHECK 1 :  Check nft list chain input
# ------------------------------------------------------------------

step_cmd_check_1 = 'nft list chain inet '+ table +' '+ chain_input +' 2>/dev/null';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(strstr(step_res_check_1, 'ip protocol tcp ct state established accept') && strstr(step_res_check_1, 'ip protocol udp ct state established accept') && strstr(step_res_check_1, 'ip protocol icmp ct state established accept')){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check nft list chain output
# ------------------------------------------------------------------

step_cmd_check_2 = 'nft list chain inet '+ table +' '+ chain_output +' 2>/dev/null';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(strstr(step_res_check_2, 'ip protocol tcp ct state established,related,new accept') && strstr(step_res_check_2, 'ip protocol udp ct state established,related,new accept') && strstr(step_res_check_2, 'ip protocol icmp ct state established,related,new accept')){
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
