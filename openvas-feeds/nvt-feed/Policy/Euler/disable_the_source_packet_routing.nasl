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
  script_oid("1.3.6.1.4.1.25623.1.0.130350");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Disable the Source Packet Routing");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.13 Disable the Source Packet Routing (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.13 Disable the Source Packet Routing (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.13 Disable the Source Packet Routing (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.13 Disable the Source Packet Routing (Requirement)");

  script_tag(name:"summary", value:"In a network, source routing allows the sender to specify some
or all routes for data packets to pass through the network. In regular routing, routers in the
network determine the path based on the destination of the data packets. If a large number of
packets are tampered with and pass through the specified router, the internal network can be
attacked. As a result, the specified router is overloaded and normal service traffic is interrupted.

Attackers can forge valid IP addresses and set source routing options and valid routers to access
the network. In addition, if the source routing data packet is allowed, an intermediate routing
address can be constructed to access the dedicated address system. If an attacker intercepts the
original packet and uses the source routing for address spoofing, the attacker can force the
specified backhaul packets to be routed back through the attacker's device. In this way, the
attacker can successfully receive bidirectional data packets. Therefore, source packet routing must
be disabled to reduce the attack surface.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Disable the Source Packet Routing";

solution = "Run the following commands to disable source packet routing:

# sysctl -w net.ipv4.conf.all.accept_source_route=0
# sysctl -w net.ipv4.conf.default.accept_source_route=0
# sysctl -w net.ipv6.conf.all.accept_source_route=0
# sysctl -w net.ipv6.conf.default.accept_source_route=0
# sysctl -w net.ipv4.route.flush=1
# sysctl -w net.ipv6.route.flush=1

Open the /etc/sysctl.conf file and add or modify the following configurations:

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# sysctl net.ipv4.conf.all.accept_source_route && sysctl net.ipv4.conf.default.accept_source_route && sysctl net.ipv6.conf.all.accept_source_route && sysctl net.ipv6.conf.default.accept_source_route';

expected_value = 'The output should match the pattern "net.ipv4.conf.all.accept_source_route = 0\\s*net.ipv4.conf.default.accept_source_route = 0\\s*net.ipv6.conf.all.accept_source_route = 0\\s*net.ipv6.conf.default.accept_source_route = 0"';

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
# CHECK : Verify command `sysctl net.ipv4.conf.all.accept_source_route`
# ------------------------------------------------------------------

step_cmd = 'sysctl net.ipv4.conf.all.accept_source_route && sysctl net.ipv4.conf.default.accept_source_route && sysctl net.ipv6.conf.all.accept_source_route && sysctl net.ipv6.conf.default.accept_source_route';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value =~ 'net.ipv4.conf.all.accept_source_route = 0\\s*net.ipv4.conf.default.accept_source_route = 0\\s*net.ipv6.conf.all.accept_source_route = 0\\s*net.ipv6.conf.default.accept_source_route = 0'){
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