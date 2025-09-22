# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811737");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-09-11 19:06:34 +0530 (Mon, 11 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Pulse Secure / Ivanti Connect Secure Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Ivanti Connect Secure (formerly Pulse
  Secure Connect Secure).");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);

if (!sysdesc = snmp_get_sysdescr(port: port))
  exit(0);

# Pulse Secure, LLC,Pulse Connect Secure,MAG-2600,8.2R4 (build 47329)
# Pulse Secure, LLC,Ivanti Connect Secure,PSA-3000,9.1R18.2 (build 24467)
# Pulse Secure, LLC,Ivanti Connect Secure,PSA-3000,9.1R14 (build 16847)
# Pulse Secure, LLC,Pulse Connect Secure,PSA-3000,9.1R13.2 (build 18121)
# Pulse Secure, LLC,Pulse Connect Secure,SA-2500,8.1R11 (build 52981)
# Pulse Secure,LLC,Pulse Connect Secure,MAG-SM160,8.1R7 (build 41041)
# Pulse Secure, LLC,Pulse Connect Secure,SA-2500,8.1R15.1 (build 59747)
# Pulse Secure, LLC,Ivanti Connect Secure,PSA-3000,9.1R18.1 (build 23821)
# Pulse Secure, LLC,Ivanti Connect Secure,ISA-V,22.3R1 (build 1647)
#
# nb: Please keep the pattern used here in sync with the one used in gb_snmp_os_detection.nasl
#
if (sysdesc =~ "(Ivanti|Pulse) Connect Secure" && "Pulse Secure" >< sysdesc) {
  model = "unknown";
  version = "unknown";

  set_kb_item(name: "pulsesecure/detected", value: TRUE);
  set_kb_item(name: "pulsesecure/snmp/port", value: port);
  set_kb_item(name: "pulsesecure/snmp/" + port + "/concluded", value: sysdesc);

  # nb: See detailed example banner above
  details = eregmatch(pattern: "Connect Secure,([^,]+),([0-9R.]+)", string: sysdesc);
  if (!isnull(details[1])) {
    model = details[1];
    version = details[2];
  }

  set_kb_item(name: "pulsesecure/snmp/" + port + "/version", value: version);
  set_kb_item(name: "pulsesecure/snmp/" + port + "/model", value: model);
}

exit(0);
