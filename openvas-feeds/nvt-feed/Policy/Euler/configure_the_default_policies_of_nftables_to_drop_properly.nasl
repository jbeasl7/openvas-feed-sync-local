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
  script_oid("1.3.6.1.4.1.25623.1.0.130354");
  script_version("2025-09-22T07:08:28+0000");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure the Default Policies of nftables to DROP Properly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_add_preference(name:"Table", type:"entry", value:"test", id:1);
  script_add_preference(name:"Chain Input", type:"entry", value:"input", id:2);
  script_add_preference(name:"Chain Output", type:"entry", value:"output", id:3);
  script_add_preference(name:"Chain Forward", type:"entry", value:"forward", id:4);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.12 Configure the Default Policies of nftables to DROP Properly (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.12 Configure the Default Policies of nftables to DROP Properly (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.12 Configure the Default Policies of nftables to DROP Properly (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.12 Configure the Default Policies of nftables to DROP Properly (Recommendation)");

  script_tag(name:"summary", value:"For security purposes, the nftables base chains (INPUT, OUTPUT,
and FORWARD) are similar to those of iptables. You need to configure the DROP policy for all
packets, and then add the ACCEPT policy to the base chains to open related services and ports.

If the base chains are not configured or the hook policy is not specified for them, packets will
not be obtained by nftables and thus cannot be filtered.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

table = script_get_preference("Table");
chain_input = script_get_preference("Chain Input");
chain_output = script_get_preference("Chain Output");
chain_forward = script_get_preference("Chain Forward");

title = "Configure the Default Policies of nftables to DROP Properly";

solution = "Create a table.

# nft add table inet <table name>

Run the following commands to configure the DROP policy for the INPUT, OUTPUT, and FORWARD base
chains in the table. Note that the network may be disconnected after the configuration.

# nft add chain inet <table name> <chain name> { type filter hook input priority 0\\<semicolon>
policy drop\\<semicolon> }
# nft add chain inet <table name> <chain name> { type filter hook output priority 0\\<semicolon>
policy drop\\<semicolon> }
# nft add chain inet <table name> <chain name> { type filter hook forward priority 0\\<semicolon>
policy drop\\<semicolon> }

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
# nft list chain inet '+ table +' '+ chain_output +' 2>/dev/null

3. Run the command in the terminal:
# nft list chain inet '+ table +' '+ chain_forward +' 2>/dev/null';

expected_value = '1. The output should contain "type filter hook input priority 0; policy drop;"
2. The output should contain "type filter hook output priority 0; policy drop;"
3. The output should contain "type filter hook forward priority 0; policy drop;"';

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

if(strstr(step_res_check_1, 'type filter hook input priority 0; policy drop;')){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check nft list chain output
# ------------------------------------------------------------------

step_cmd_check_2 = 'nft list chain inet '+ table +' '+ chain_output +' 2>/dev/null';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(strstr(step_res_check_2, 'type filter hook output priority 0; policy drop;')){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 3 :  Check nft list chain forward
# ------------------------------------------------------------------

step_cmd_check_3 = 'nft list chain inet '+ table +' '+ chain_forward +' 2>/dev/null';
step_res_check_3 = ssh_cmd(socket:sock, cmd:step_cmd_check_3, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '3. ' + step_res_check_3 + '\n';
check_result_3 = FALSE;

if(strstr(step_res_check_3, 'type filter hook forward priority 0; policy drop;')){
  check_result_3 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------
if(check_result_1 && check_result_2 && check_result_3){
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
