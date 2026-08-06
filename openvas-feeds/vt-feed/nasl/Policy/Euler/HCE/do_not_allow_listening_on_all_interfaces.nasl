# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.134055");
  script_version("2026-08-05T06:26:26+0000");
  script_tag(name:"last_modification", value:"2026-08-05 06:26:26 +0000 (Wed, 05 Aug 2026)");
  script_tag(name:"creation_date", value:"2026-07-20 00:00:00 +0000 (Mon, 20 Jul 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Allow Listening on All Interfaces");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "compliance_os_check.nasl");
  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/hce");

  script_add_preference(name:"Status", type:"radio", value:"Incomplete;Not Compliant;Compliant", id:1);

  script_xref(name:"Policy", value:"Huawei Cloud HCE 2.0 Security Configuration Baseline: 1.4.3 Do Not Allow Listening on All Interfaces (Required)(Manual)");

  script_tag(name:"summary", value:"A server-side product must not bind to the IP address 0.0.0.0
  if doing so would compromise the host's network isolation. In such cases, binding to 0.0.0.0
  should be prohibited. (This rule is not applied when a host acts as a client.) Different network
  planes must bind to their own dedicated IP addresses.

  Binding to 0.0.0.0 means binding to all IP addresses of a host, resulting in listening on all
  networks. This violates the system's isolation model if the host separates management, control,
  and user planes (such as a three-plane isolation design). For a host that is connected to both
  the Internet and a local area network (LAN), any port intended to be exposed on the LAN side must
  be bound to a LAN-side IP address and must not be bound to 0.0.0.0.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Allow Listening on All Interfaces";

solution = "For listening ports that do not need to remain open continuously, they can be enabled
when needed and disabled when not in use to reduce the exposure window.

For example, if the listening IP address of port 22 is 0.0.0.0, modify the /etc/ssh/sshd_config
file to add listening IP addresses in the file. You can configure multiple listening IP addresses
based on environment requirements.

ListenAddress listening-IP-address 1
ListenAddress listening-IP-address 2

Restart the sshd service after the configuration is complete.
# systemctl restart sshd";

check_type = "Manual";

action = "Needs manual check";

expected_value = script_get_preference("Status", id:1);

actual_value = expected_value;

if(expected_value == "Incomplete"){
  compliant = "incomplete";
  comment = "Marked as incomplete via Policy.";
}else if(expected_value == "Compliant"){
  compliant = "yes";
  comment = "Marked as compliant via Policy after manual listening-socket validation.";
}else if(expected_value == "Not Compliant"){
  compliant = "no";
  comment = "Marked as non-compliant via Policy.";
}

target = get_kb_item("policy/ssh/login/os-release");
comment = "Target: " + target + "\n" + comment;

report_audit(action: action,
             actual_value: actual_value,
             expected_value: expected_value,
             is_compliant: compliant,
             solution: solution,
             check_type: check_type,
             title: title,
             comment: comment);

exit(0);
