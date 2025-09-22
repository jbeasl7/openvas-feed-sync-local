# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
# SPDX-License-Identifier: GPL-2.0-only

# ------------------------------------------------------------------
# METADATA
# ------------------------------------------------------------------

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130335");
  script_version("2025-08-06T05:45:41+0000");
  script_tag(name:"last_modification", value:"2025-08-06 05:45:41 +0000 (Wed, 06 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Disable IP Forwarding");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.12 Disable IP Forwarding (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.12 Disable IP Forwarding (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.12 Disable IP Forwarding (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.12 Disable IP Forwarding (Requirement)");

  script_tag(name:"summary", value:"If a node does not function as a gateway server, disable the IP
forwarding function. Otherwise, attackers can use the node as a router.

In the container scenario, if network packets need to be forwarded through the host, IP forwarding
is allowed.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Disable IP Forwarding";

solution = "Run the following commands to disable IP forwarding and modify the configuration files:

# grep -Els `^\s*net\.ipv4\.ip_forward\s*=\s*1` /etc/sysctl.conf /etc/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf <pipe> while read filename<semicolon> do sed -ri
`s/^\s*(net\.ipv4\.ip_forward\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/` $filename<semicolon>
done<semicolon> sysctl -w net.ipv4.ip_forward=0<semicolon> sysctl -w net.ipv4.route.flush=1

# grep -Els `^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1` /etc/sysctl.conf /etc/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf <pipe> while read filename<semicolon> do sed -ri
`s/^\s*(net\.ipv6\.conf\.all\.forwarding\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/` $filename<semicolon>
done<semicolon> sysctl -w net.ipv6.conf.all.forwarding=0<semicolon> sysctl -w net.ipv6.route.flush=1";

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal :
# sysctl net.ipv4.ip_forward
2. Run the command in the terminal :
# sysctl net.ipv6.conf.all.forwarding';

expected_value = 'The output should contain a "net.ipv4.ip_forward = 0 net.ipv6.conf.all.forwarding = 0" or be empty';

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
# CHECK 1 :  Verify command `sysctl net.ipv4.ip_forward`
# ------------------------------------------------------------------

step_cmd = 'sysctl net.ipv4.ip_forward && sysctl net.ipv6.conf.all.forwarding';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value =~ 'net.ipv4.ip_forward = 0\\s*net.ipv6.conf.all.forwarding = 0' || !actual_value || (actual_value =~ 'net.ipv4.ip_forward = 0' && !actual_value) || (actual_value =~ 'net.ipv6.conf.all.forwarding = 0' && !actual_value)){
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