# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112772");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2020-06-30 13:23:11 +0000 (Tue, 30 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SATO Printer Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of SATO printers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port( default: 161 );

sysdesc = snmp_get_sysdescr( port: port );
if( ! sysdesc )
  exit( 0 );

# SATO CL6NX-J 203dpi
# SATO LR4NX-FA 305dpi
if( sysdesc =~ "^SATO " ) {
  set_kb_item( name: "sato_printer/detected", value: TRUE );
  set_kb_item( name: "sato_printer/snmp/detected", value: TRUE );
  set_kb_item( name: "sato_printer/snmp/port", value: port );
  set_kb_item( name: "sato_printer/snmp/" + port + "/concluded", value: sysdesc );

  mod = eregmatch( pattern: "SATO ([^\r\n]+)", string: sysdesc );
  if( ! isnull( mod[1] ) ) {
    set_kb_item( name: "sato_printer/snmp/" + port + "/model", value: mod[1] );
  }

  exit( 0 );
}

exit( 0 );
