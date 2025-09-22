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
  script_oid("1.3.6.1.4.1.25623.1.0.130349");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Disable the ARP Proxy");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.19 Disable the ARP Proxy (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.19 Disable the ARP Proxy (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.19 Disable the ARP Proxy (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.19 Disable the ARP Proxy (Requirement)");

  script_tag(name:"summary", value:"The ARP proxy allows the system to respond to ARP requests on
another interface on behalf of a host connected to an interface. Disabling the ARP proxy not only
prevents unauthorized information sharing, but also prevents addressing information leakage between
connected network segments. Therefore, the ARP proxy must be disabled to prevent ARP packet attacks
from affecting the system.

By default, the ARP proxy is disabled in openEuler. You can modify it as required.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Disable the ARP Proxy";

solution = "1. Run the following commands to temporarily disable the ARP proxy. After the reboot,
the default values are restored.

# sysctl -w net.ipv4.conf.all.proxy_arp=0
# sysctl -w net.ipv4.conf.default.proxy_arp=0

2. Open the /etc/sysctl.conf file, add or modify the following configurations, and run the sysctl
-p /etc/sysctl.conf command to make the configurations take effect permanently.

net.ipv4.conf.all.proxy_arp=0
net.ipv4.conf.default.proxy_arp=0";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# sysctl net.ipv4.conf.all.proxy_arp && sysctl net.ipv4.conf.default.proxy_arp';

expected_value = 'The output should match the pattern "net.ipv4.conf.all.proxy_arp = 0\\\\s*net.ipv4.conf.default.proxy_arp = 0"';

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
# CHECK : Verify command `sysctl net.ipv4.conf.all.proxy_arp && sysctl net.ipv4.conf.default.proxy_arp`
# ------------------------------------------------------------------
step_cmd = 'sysctl net.ipv4.conf.all.proxy_arp && sysctl net.ipv4.conf.default.proxy_arp';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value =~ 'net.ipv4.conf.all.proxy_arp = 0\\s*net.ipv4.conf.default.proxy_arp = 0'){
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