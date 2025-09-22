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
  script_oid("1.3.6.1.4.1.25623.1.0.130330");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Enable Reverse Path Filtering");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.11 Enable Reverse Path Filtering (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.11 Enable Reverse Path Filtering (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.11 Enable Reverse Path Filtering (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.11 Enable Reverse Path Filtering (Requirement)");

  script_tag(name:"summary", value:"Setting net.ipv4.conf.all.rp_filter and
net.ipv4.conf.default.rp_filter to 1 forces the Linux kernel to perform reverse path filtering on a
received packet and check the validity of its source address. If the Linux kernel queries the
routing table in which the source address is included and finds that the optimal outbound port of
the next hop of the source address is not the inbound port of the received packet, it discards the
packet.

Attackers can perform IP address spoofing, which is widely used in network attacks. When receiving
a data packet through reverse address filtering and obtaining the source IP address from the
packet, the Linux kernel checks whether the routing table of the router contains the routing
information of the data packet. If the routing table does not contain the routing information used
for data return, it is very likely that this packet is forged. In this case, the router discards
this packet.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Enable Reverse Path Filtering";

solution = "Run the following commands to enable reverse path filtering.

# sysctl -w net.ipv4.conf.all.rp_filter=1
# sysctl -w net.ipv4.conf.default.rp_filter=1
# sysctl -w net.ipv4.route.flush=1

Open the /etc/sysctl.conf file and add or modify the following configurations:

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# sysctl net.ipv4.conf.all.rp_filter && sysctl net.ipv4.conf.default.rp_filter';

expected_value = 'The output should match the pattern "net.ipv4.conf.all.rp_filter\\s*=\\s*1\\s*net.ipv4.conf.default.rp_filter = 1"';

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
# CHECK : Verify command  sysctl net.ipv4.conf.all.rp_filter && sysctl net.ipv4.conf.default.rp_filter
# ------------------------------------------------------------------

step_cmd = 'sysctl net.ipv4.conf.all.rp_filter && sysctl net.ipv4.conf.default.rp_filter';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value =~ 'net.ipv4.conf.all.rp_filter\\s*=\\s*1\\s*net.ipv4.conf.default.rp_filter = 1'){
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