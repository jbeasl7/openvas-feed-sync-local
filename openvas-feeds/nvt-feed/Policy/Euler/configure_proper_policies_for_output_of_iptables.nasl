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
  script_oid("1.3.6.1.4.1.25623.1.0.130362");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure Proper Policies for OUTPUT of iptables");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_add_preference(name:"Protocol", type:"entry", value:"tcp", id:1);
  script_add_preference(name:"Port", type:"entry", value:"22", id:2);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.9 Configure Proper Policies for OUTPUT of iptables (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.9 Configure Proper Policies for OUTPUT of iptables (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.9 Configure Proper Policies for OUTPUT of iptables (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.9 Configure Proper Policies for OUTPUT of iptables (Recommendation)");

  script_tag(name:"summary", value:"There are two occasions in which a server sends outgoing
packets: 1. The local host process proactively connects to an external server, for example,
performing an HTTP access, or sending data to a log server. 2. The local host responds to the
external access to the local services.

If no policy is configured for the OUTPUT chain, all outgoing packets from the server are discarded
because the default policy is DROP.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

protocol = script_get_preference("Protocol");
port = script_get_preference("Port");

title = "Configure Proper Policies for OUTPUT of iptables";

solution = "Run the following command to add the ACCEPT policy to the OUTPUT chain:

# iptables -A OUTPUT -p <protocol> -s <source ip> -d <dest ip> --sport <src port> -j ACCEPT

Example:
# iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT

Run the following command to make the configured policy take effect permanently:

# service iptables save
iptables: Saving firewall rules to /etc/sysconfig/iptables: [  OK  ]

Run the following command to configure the IPv6-based policy:

# ip6tables -A OUTPUT -p <protocol> -s <source ip> -d <dest ip> --sport <src port> -j ACCEPT

Example:
# ip6tables -A OUTPUT -p tcp --sport 22 -j ACCEPT

Run the following command to make the configured policy take effect permanently:

# service ip6tables save
ip6tables: Saving firewall rules to /etc/sysconfig/ip6tables: [  OK  ]";

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# iptables-save 2>/dev/null | grep -E "^-A OUTPUT.+\\<'+ protocol +'\\>.+\\<'+ port +'\\>.+ACCEPT$"

2. Run the command in the terminal:
# ip6tables-save 2>/dev/null | grep -E "^-A OUTPUT.+\\<'+ protocol +'\\>.+\\<'+ port +'\\>.+ACCEPT$"';

expected_value = '1. The output should not be empty
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
# CHECK 1 :  Check protokol in iptables
# ------------------------------------------------------------------

step_cmd_check_1 = 'iptables-save 2>/dev/null | grep -E "^-A OUTPUT.+\\<'+ protocol +'\\>.+\\<'+ port +'\\>.+ACCEPT$"';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check protokol in ip6tables
# ------------------------------------------------------------------

step_cmd_check_2 = 'ip6tables-save 2>/dev/null | grep -E "^-A OUTPUT.+\\<'+ protocol +'\\>.+\\<'+ port +'\\>.+ACCEPT$"';
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
