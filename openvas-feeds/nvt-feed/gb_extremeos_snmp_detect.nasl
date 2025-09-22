# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106413");
  script_version("2023-10-24T14:40:27+0000");
  script_tag(name:"last_modification", value:"2023-10-24 14:40:27 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"creation_date", value:"2016-11-25 11:50:20 +0700 (Fri, 25 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Extreme ExtremeXOS (EXOS) Detection (SNMP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/detected");

  script_tag(name:"summary", value:"SNMP based detection of Extreme ExtremeXOS (EXOS).");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);

# ExtremeXOS (X440G2-24x-10G4) version 21.1.3.7 21.1.3.7 by release-manager on Mon Jan 30 10:47:48 EST 2017
# ExtremeXOS (X440G2-12p-10G4) version 31.7.1.4 31.7.1.4-patch1-36 by release-manager on Thu Jul 21 10:39:54 EDT 2022
# ExtremeXOS version 12.3.3.6 v1233b6-patch1-6 by release-manager on Tue Feb 2 07:25:47 PST 2010
if (!sysdesc || "ExtremeXOS" >!< sysdesc) {
  man_oid = "1.3.6.1.2.1.47.1.1.1.1.12.1";
  man = snmp_get(port: port, oid: man_oid);
  if (!man || man !~ "^Extreme Networks")
    exit(0);
}

model = "unknown";
version = "unknown";
patch = "None";

set_kb_item(name: "extreme/exos/detected", value: TRUE);
set_kb_item(name: "extreme/exos/snmp/detected", value: TRUE);
set_kb_item(name: "extreme/exos/snmp/port", value: port);
if (sysdesc)
  set_kb_item(name: "extreme/exos/snmp/" + port + "/concluded", value: sysdesc);

mod = eregmatch(pattern: "ExtremeXOS \(([a-zA-Z0-9-]+)", string: sysdesc);
if (isnull(mod[1])) {
  mod_oid = "1.3.6.1.2.1.47.1.1.1.1.2.1";
  mod = snmp_get(port: port, oid: mod_oid);
  if (mod && mod =~ "^X") {
    model = mod;
    set_kb_item(name: "extreme/exos/snmp/" + port + "/concludedMod", value: mod);
    set_kb_item(name: "extreme/exos/snmp/" + port + "/concludedModOID", value: mod_oid);
  } else {
    mod_oid = "1.3.6.1.2.1.47.1.1.1.1.2.3";
    mod = snmp_get(port: port, oid: mod_oid);
    if (mod && mod =~ "^X") {
      model = mod;
      set_kb_item(name: "extreme/exos/snmp/" + port + "/concludedMod", value: mod);
      set_kb_item(name: "extreme/exos/snmp/" + port + "/concludedModOID", value: mod_oid);
    }
  }
} else {
  model = mod[1];
}

if (sysdesc) {
  vers = eregmatch(pattern: "ExtremeXOS .*version ([0-9.]+)", string: sysdesc);
  if (!isnull(vers[1]))
    version = vers[1];
} else {
  vers_oid = "1.3.6.1.2.1.16.19.2.0";
  vers = snmp_get(port: port, oid: vers_oid);
  if (vers) {
    version = vers;
    set_kb_item(name: "extreme/exos/snmp/" + port + "/concludedVers", value: vers);
    set_kb_item(name: "extreme/exos/snmp/" + port + "/concludedVersOID", value: vers_oid);
  }
}

p = eregmatch(pattern: "-patch([0-9-]+)", string: sysdesc);
if (!isnull(p[1]))
  patch = p[1];

set_kb_item(name: "extreme/exos/snmp/" + port + "/model", value: model);
set_kb_item(name: "extreme/exos/snmp/" + port + "/version", value: version);
set_kb_item(name: "extreme/exos/snmp/" + port + "/patch", value: patch);

exit(0);
