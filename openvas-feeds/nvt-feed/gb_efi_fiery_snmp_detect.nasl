# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146701");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2021-09-13 11:59:41 +0000 (Mon, 13 Sep 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("EFI Fiery Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of EFI Fiery.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

if (!sysdesc = snmp_get_sysdescr(port: port))
  exit(0);

# Fiery PRO80 80C-KM
# Fiery X3eTY 50_45C-KM
if (sysdesc =~ "^Fiery ") {
  model = "unknown";
  version = "unknown";

  set_kb_item(name: "efi/fiery/detected", value: TRUE);
  set_kb_item(name: "efi/fiery/snmp/detected", value: TRUE);
  set_kb_item(name: "efi/fiery/snmp/port", value: port);
  set_kb_item(name: "efi/fiery/snmp/" + port + "/concluded", value: sysdesc);
  set_kb_item(name: "efi/fiery/snmp/" + port + "/model", value: model);
  set_kb_item(name: "efi/fiery/snmp/" + port + "/version", value: version);
}

exit(0);
