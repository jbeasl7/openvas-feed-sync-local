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
  script_oid("1.3.6.1.4.1.25623.1.0.130369");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure the iptables Policies for Loopback Properly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.7 Configure the iptables Policies for Loopback Properly (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.7 Configure the iptables Policies for Loopback Properly (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.7 Configure the iptables Policies for Loopback Properly (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.7 Configure the iptables Policies for Loopback Properly (Recommendation)");

  script_tag(name:"summary", value:"The loopback address (127.0.0.0/8) is a special address on a
server. It is irrelevant to NICs and is mainly used for the inter-process communication of a local
device. Packets with the source address 127.0.0.0/8 from NICs should be discarded. If policies
related to the loopback address are improperly configured, the inter-process communication of the
local device may fail or spoofing packets may be received from the NICs.

Policies need to be set on the server to allow the server to receive and process packets with the
loopback address from the lo interface, but reject packets from the NICs.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure the iptables Policies for Loopback Properly";

solution = "Run the following commands to enable a server to receive and process packets from the
lo interface, but reject packets from 127.0.0.0/8. iptables matches rules in sequence. Therefore,
the DROP rule must be added after the other two rules. Otherwise, the packets (source address:
127.0.0.0/8) sent by the lo interface will be discarded when the DROP rule is matched.

# iptables -A INPUT -i lo -j ACCEPT
# iptables -A OUTPUT -o lo -j ACCEPT
# iptables -A INPUT -s 127.0.0.0/8 -j DROP

Run the following command to make the configured policies take effect permanently:

# service iptables save
iptables: Saving firewall rules to /etc/sysconfig/iptables: [  OK  ]

Run the following commands to configure the IPv6-based policies:

# ip6tables -A INPUT -i lo -j ACCEPT
# ip6tables -A OUTPUT -o lo -j ACCEPT
# ip6tables -A INPUT -s ::1 -j DROP

Run the following command to make the configured policies take effect permanently:

# service ip6tables save
ip6tables: Saving firewall rules to /etc/sysconfig/ip6tables: [  OK  ]";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# (iptables-save | grep -Fq -- \'-A INPUT -i lo -j ACCEPT\' && iptables-save | grep -Fq -- \'-A INPUT -s 127.0.0.0/8 ! -i lo -j DROP\' && iptables-save | grep -Fq -- \'-A OUTPUT -o lo -j ACCEPT\' && ip6tables-save | grep -Fq -- \'-A INPUT -i lo -j ACCEPT\' && (ip6tables-save | grep -Fq -- \'-A INPUT -s ::1 ! -i lo -j DROP\' || ip6tables-save | grep -Fq -- \'-A INPUT -s ::1/128 ! -i lo -j DROP\') && ip6tables-save | grep -Fq -- \'-A OUTPUT -o lo -j ACCEPT\' && echo PASSED) || echo FAILED';

expected_value = 'The output should be equal to "PASSED"';

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

# ------------------------------------------------------------------
# CHECK : Check iptables rules
# ------------------------------------------------------------------

step_cmd = '(iptables-save | grep -Fq -- \'-A INPUT -i lo -j ACCEPT\' && iptables-save | grep -Fq -- \'-A INPUT -s 127.0.0.0/8 ! -i lo -j DROP\' && iptables-save | grep -Fq -- \'-A OUTPUT -o lo -j ACCEPT\' && ip6tables-save | grep -Fq -- \'-A INPUT -i lo -j ACCEPT\' && (ip6tables-save | grep -Fq -- \'-A INPUT -s ::1 ! -i lo -j DROP\' || ip6tables-save | grep -Fq -- \'-A INPUT -s ::1/128 ! -i lo -j DROP\') && ip6tables-save | grep -Fq -- \'-A OUTPUT -o lo -j ACCEPT\' && echo PASSED) || echo FAILED';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value == 'PASSED'){
  compliant = "yes";
  comment = "Check passed";
}else{
  compliant = "no";
  comment = "Check failed";
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
