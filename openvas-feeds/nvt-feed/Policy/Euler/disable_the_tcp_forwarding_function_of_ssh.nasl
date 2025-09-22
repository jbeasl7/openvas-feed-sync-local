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
  script_oid("1.3.6.1.4.1.25623.1.0.130323");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:19 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Disable the TCP Forwarding Function of SSH");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.21 Disable the TCP Forwarding Function of SSH (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.21 Disable the TCP Forwarding Function of SSH (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.21 Disable the TCP Forwarding Function of SSH (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.21 Disable the TCP Forwarding Function of SSH (Requirement)");

  script_tag(name:"summary", value:"Setting AllowTcpForwarding to no disables the SSH client from
performing TCP port forwarding. TCP port forwarding is a function of transmitting data between a
local host and a remote host through an SSH tunnel. By disabling this function, you can restrict
the data transmission and access scope of users in SSH sessions to enhance system security.

The impacts of the configuration are as follows:

1. Restricting data transmission: Disabling TCP port forwarding prevents users from transmitting
data in SSH sessions, reducing possible data leakage risks.
2. Reducing the attack surface: Enabling TCP port forwarding may introduce some security risks, for
example, allowing attackers to evade network security measures or access restricted services.
Disabling this function can reduce the attack surface of the system.
3. Avoiding resource abuse: TCP port forwarding may occupy server resources and bandwidth.
Disabling TCP port forwarding can prevent resource abuse.
4. Compliance with security best practices: In some cases, such as environments with high security
requirements, disabling TCP port forwarding may be one of the security best practices.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Disable the TCP Forwarding Function of SSH";

solution = "Open the /etc/ssh/sshd_config file, and modify or add the AllowTcpForwarding
configuration as follows:

# vim /etc/ssh/sshd_config
AllowTcpForwarding no
# systemctl restart sshd";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# sshd -T -C user=root -C host="$(hostname)" -C addr=$"(grep $(hostname)) /etc/hosts" | grep "allowtcpforwarding"';

expected_value = 'The output should be equal to "allowtcpforwarding no"';

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
# CHECK : Verify command sshd -T -C user=root -C host="$(hostname)" -C addr=$"(grep $(hostname)) /etc/hosts" | grep "allowtcpforwarding"
# ------------------------------------------------------------------

step_cmd = 'sshd -T -C user=root -C host="$(hostname)" -C addr=$"(grep $(hostname)) /etc/hosts" | grep "allowtcpforwarding"';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value == 'allowtcpforwarding no'){
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