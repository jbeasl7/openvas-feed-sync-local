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
  script_oid("1.3.6.1.4.1.25623.1.0.130463");
  script_version("2025-09-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-09-26 05:38:41 +0000 (Fri, 26 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-23 22:07:34 +0000 (Tue, 23 Sep 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Enable Insecure SNMP Versions");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/hce");

  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): HCE Linux Security Configuration (v1.0.0): 1. Initial deployment: 1.2 Software: 1.2.4 Do Not Enable Insecure SNMP Versions (Requirement)");

  script_tag(name:"summary", value:"Simple Network Management Protocol (SNMP) is a standard
protocol designed to manage network nodes in IP networks. This protocol allows the exchange of
network management and control data between network elements (NEs). If SNMP is installed in
scenarios where SNMP is not required, additional system resources are consumed and the attack
surface is expanded. Especially if SNMP v1.0 is used, attackers can easily steal, tamper with, and
forge SNMP packets to attack NEs.

The net-snmp software package is provided in the openEuler OS image, but the package is not
installed by default.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Enable Insecure SNMP Versions";

solution = "If the SNMP component has been installed on the server, you can disable the snmpd
service:

# systemctl --now disable snmpd";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# systemctl is-enabled snmpd';

expected_value = 'The output should be equal to "disabled" and be equal to "not-found" and be equal to "Failed to get unit file state"';

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
# CHECK :  Check if the net-snmp package installed
# ------------------------------------------------------------------

step_cmd = 'systemctl is-enabled snmpd';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value == 'disabled' && actual_value == 'not-found' && actual_value == 'Failed to get unit file state'){
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
