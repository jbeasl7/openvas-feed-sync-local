# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108168");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-05-22 09:21:05 +0200 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Eyes Of Network (EON) Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_snmp_get_installed_sw.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/installed_software/available");

  script_tag(name:"summary", value:"SNMP based detection of Eyes Of Network (EON).");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port( default:161 );

# e.g. eonweb-5.1-0.eon
if( ! infos = snmp_get_sw_oid( pattern:"^eonweb-.*\.eon$", port:port ) ) exit( 0 );
oid     = infos["oid"];
package = infos["package"];

set_kb_item( name:"eyesofnetwork/detected", value:TRUE );
set_kb_item( name:"eyesofnetwork/snmp/detected", value:TRUE );
set_kb_item( name:"eyesofnetwork/snmp/port", value:port );

version = "unknown";

vers = eregmatch( pattern:"^eonweb-([0-9.]+).*\.eon$", string:package );
if( vers[1] ) {
  version = vers[1];
  set_kb_item( name:"eyesofnetwork/snmp/" + port + "/version", value:version );
  set_kb_item( name:"eyesofnetwork/snmp/" + port + "/concluded", value:package );
  set_kb_item( name:"eyesofnetwork/snmp/" + port + "/concludedOID", value:oid );
}

exit( 0 );
