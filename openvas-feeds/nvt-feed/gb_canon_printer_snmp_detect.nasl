# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147493");
  script_version("2025-04-07T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-04-07 05:39:52 +0000 (Mon, 07 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-01-20 08:31:45 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Canon Printer Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Canon printer devices.");

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

# e.g.:
# Canon iR1024 /P
# Canon MF240 Series /P
# nb: Case insensitive match (via "=~") is expected / done on purpose
if (sysdesc !~ "^Canon [A-Za-z]")
  exit(0);

model = "unknown";
fw_version = "unknown";

set_kb_item(name: "canon/printer/detected", value: TRUE);
set_kb_item(name: "canon/printer/snmp/detected", value: TRUE);
set_kb_item(name: "canon/printer/snmp/port", value: port);
set_kb_item(name: "canon/printer/snmp/" + port + "/banner", value: sysdesc);

# nb: Using Canon-specific MIBs as seen in
# https://github.com/gitpan/CPM/blob/master/lib/CPM.pm
# https://github.com/Tylan/check_snmp_printer/blob/master/check_snmp_printer

# MF745C/746C
# Canon MF210 Series
# iR-ADV C3826
# imageRUNNER1133 series
mod_oid = "1.3.6.1.4.1.1602.1.1.1.1.0";
m = snmp_get(port: port, oid: mod_oid);
if (!isnull(m)) {
  mod = eregmatch(pattern: "^(Canon )?([^/]+)", string: m, icase: TRUE);
} else {
  # nb: Fallback to the more generic MIB as was previously implemented
  # eg. Canon iR1025 /P
  # Canon MF230 Series /P
  # Canon iR2006/2206 /P
  # Canon imageRUNNER1133 series /P
  mod_oid = "1.3.6.1.2.1.25.3.2.1.3.1";
  m = snmp_get(port: port, oid: mod_oid);
  mod = eregmatch(pattern: "^(Canon )?((iR-ADV )?([^/ ]+)).*", string: m, icase: TRUE);
}

if (!isnull(mod[2])) {
  model = mod[2];
  set_kb_item(name: "canon/printer/snmp/" + port + "/concludedMod", value: mod[0]);
  set_kb_item(name: "canon/printer/snmp/" + port + "/concludedModOID", value: mod_oid);
}

ver_oid = "1.3.6.1.4.1.1602.1.1.1.4.0";
v = snmp_get(port: port, oid: ver_oid);

# nb: We need to eliminate some weird cases that does not look like a valid version, like
# 0604
# GFC-015-04
ver = eregmatch(pattern: "^([0-9]+\.[.0-9]+)", string: v);
if (!isnull(ver[1])) {
  fw_version = ver[1];
  set_kb_item(name: "canon/printer/snmp/" + port + "/concludedFwOID", value: ver_oid);
}

set_kb_item(name: "canon/printer/snmp/" + port + "/model", value: model);
set_kb_item(name: "canon/printer/snmp/" + port + "/fw_version", value: fw_version);

exit(0);
