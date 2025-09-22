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
  script_oid("1.3.6.1.4.1.25623.1.0.130355");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure the Default Policies of iptables to DROP Properly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.6  Configure the Default Policies of iptables to DROP Properly (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.6  Configure the Default Policies of iptables to DROP Properly (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.6  Configure the Default Policies of iptables to DROP Properly (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.6  Configure the Default Policies of iptables to DROP Properly (Recommendation)");

  script_tag(name:"summary", value:"Generally, iptables policies can be configured in allowlist or
blocklist mode. You are advised to configure iptables policies in allowlist mode. Connections that
do not comply with the rules in the allowlist are prohibited. Therefore, you can configure the DROP
or REJECT policy for the INPUT, OUTPUT, and FORWARD chains, and then configure the ACCEPT policy
for the ports and services to be opened.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure the Default Policies of iptables to DROP Properly";

solution = 'Run the following commands to set the default policies of the INPUT, OUTPUT, and
FORWARD chains to DROP. Note that if you perform remote configuration through the network
connection, the network is disconnected after the policies are modified. In this case, you need to
configure the connection through the serial port.

# iptables -A INPUT -j DROP
# iptables -A OUTPUT -j DROP
# iptables -A FORWARD -j DROP

Run the following command to make the configured policies take effect permanently:

# service iptables save
iptables: Saving firewall rules to /etc/sysconfig/iptables: [  OK  ]

Run the following commands to configure the default IPv6-based policies:

# ip6tables -A INPUT -j DROP
# ip6tables -A OUTPUT -j DROP
# ip6tables -A FORWARD -j DROP

Run the following command to make the configured policies take effect permanently:

# service ip6tables save
ip6tables: Saving firewall rules to /etc/sysconfig/ip6tables: [  OK  ]';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# iptables -L | grep -E "INPUT|OUTPUT|FORWARD"

2. Run the command in the terminal:
# ip6tables -L | grep -E "INPUT|OUTPUT|FORWARD"';

expected_value = '1. The output should match the pattern "Chain INPUT \\(policy DROP\\)\\s*Chain FORWARD \\(policy DROP\\)\\s*Chain OUTPUT \\(policy DROP\\)"
2. The output should match the pattern "Chain INPUT \\(policy DROP\\)\\s*Chain FORWARD \\(policy DROP\\)\\s*Chain OUTPUT \\(policy DROP\\)"';

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
# CHECK 1 :  Verify command `iptables -L | grep -E "INPUT|OUTPUT|FORWARD"`
# ------------------------------------------------------------------

step_cmd_check_1 = 'iptables -L | grep -E "INPUT|OUTPUT|FORWARD"';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 =~ 'Chain INPUT \\(policy DROP\\)\\s*Chain FORWARD \\(policy DROP\\)\\s*Chain OUTPUT \\(policy DROP\\)'){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify command `ip6tables -L | grep -E "INPUT|OUTPUT|FORWARD"`
# ------------------------------------------------------------------

step_cmd_check_2 = 'ip6tables -L | grep -E "INPUT|OUTPUT|FORWARD"';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(step_res_check_2 =~ 'Chain INPUT \\(policy DROP\\)\\s*Chain FORWARD \\(policy DROP\\)\\s*Chain OUTPUT \\(policy DROP\\)'){
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