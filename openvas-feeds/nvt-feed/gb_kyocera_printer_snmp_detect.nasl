# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147518");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2022-01-26 09:22:03 +0000 (Wed, 26 Jan 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kyocera Printer Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Kyocera printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# KYOCERA Document Solutions Printing System
if (sysdesc =~ "^KYOCERA Document Solutions Printing System") {
  model = "unknown";
  fw_version = "unknown";
  hw_version = "unknown";

  set_kb_item(name: "kyocera/printer/detected", value: TRUE);
  set_kb_item(name: "kyocera/printer/snmp/detected", value: TRUE);
  set_kb_item(name: "kyocera/printer/snmp/port", value: port);
  set_kb_item(name: "kyocera/printer/snmp/" + port + "/banner", value: sysdesc);



  # ECOSYS M5521cdn
  # TASKalfa 2553ci
  mod_oid = "1.3.6.1.4.1.1347.43.5.1.1.1.1";
  mod = chomp(snmp_get(port: port, oid: mod_oid));
  if (isnull(mod) || mod == "") {
    # nb: If the vendor-specific MIB does not work, fallback to the generic one
    mod_oid = "1.3.6.1.2.1.25.3.2.1.3.1";
    mod = chomp(snmp_get(port: port, oid: mod_oid));
  }

  if (!isnull(mod) && mod != "") {
    model = mod;
    set_kb_item(name: "kyocera/printer/snmp/" + port + "/concludedMod", value: mod);
    set_kb_item(name: "kyocera/printer/snmp/" + port + "/concludedModOID", value: mod_oid);
  }

  fw_oid = "1.3.6.1.4.1.1347.43.5.4.1.5.1.1";
  vers = snmp_get(port: port, oid: fw_oid);
  if (isnull(vers)|| vers == "") {
    # nb: If the vendor-specific MIB does not work, fallback to the previously used one
    fw_oid = "1.3.6.1.2.1.43.15.1.1.6.1.1";
    vers = snmp_get(port: port, oid: fw_oid);
  }

  if (!isnull(vers) && vers != "") {
    fw_version = vers;
    set_kb_item(name: "kyocera/printer/snmp/" + port + "/concludedFwOID", value: fw_oid);
  }

  set_kb_item(name: "kyocera/printer/snmp/" + port + "/model", value: model);
  set_kb_item(name: "kyocera/printer/snmp/" + port + "/fw_version", value: fw_version);
}

exit(0);
