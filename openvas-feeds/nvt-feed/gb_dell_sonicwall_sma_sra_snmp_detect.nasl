# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107118");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-01-09 13:26:09 +0700 (Mon, 09 Jan 2017)");

  script_name("SonicWall / Dell SonicWALL SMA / SRA Detection (SNMP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of SonicWall / Dell SonicWALL Secure Mobile
  Access (SMA) and Secure Remote Access (SRA) devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = snmp_get_port( default:161 );
sysdesc = snmp_get_sysdescr( port:port );

mod_oid = "1.3.6.1.4.1.8741.2.1.1.1.0";

if( ! sysdesc || sysdesc !~ "(Dell )?SonicWALL (S[RM]A|SSL-VPN)" ) {
  mod = snmp_get( port:port, oid:mod_oid );
  if( mod !~ "S[RM]A ([0-9]+)" &&
      mod != "EX-Virtual" ) # Virtual appliances seem to not include the model
    exit( 0 );
}

set_kb_item( name:"sonicwall/sra_sma/detected", value:TRUE );
set_kb_item( name:"sonicwall/sra_sma/snmp/port", value:port );
concluded = '\n    sysDescr OID: ' + sysdesc;

product = "unknown";
version = "unknown";
series = "unknown";

prod = eregmatch( pattern:"(Dell )?SonicWALL (S[RM]A|SSL-VPN)", string:sysdesc, icase:TRUE );
if( ! isnull( prod[2] ) )
  product = prod[2];

if( sysdesc =~ "(Dell )?SonicWALL S[R|M]A Virtual Appliance" ) {
  series = "Virtual Appliance";

  # Dell SonicWALL SRA Virtual Appliance ( 8.1.0.10-25sv)
  vers = eregmatch( string:sysdesc, pattern:"(Dell )?SonicWALL S[RM]A Virtual Appliance \( ([0-9.]+[^)]+)",
                    icase:TRUE );

  if( ! isnull( vers[2] ) )
    version = vers[2];
} else {
  # Dell SonicWALL SRA 4600 ( 8.5.0.0-13sv.03.jpn)
  # SonicWALL SRA 1200 (SonicOS SSL-VPN 4.0.0.3-20sv)
  # Dell SonicWALL SRA 4200 (SonicOS SSL-VPN 7.5.1.2-40sv)
  # SonicWall SRA 4600 (9.0.0.4-18sv)
  # Dell SonicWALL SRA 1600 ( 8.5.0.0-13sv)
  # SonicWall SMA 400 (9.0.0.3-17sv)
  # SonicWALL SSL-VPN 2000 (SonicOS SSL-VPN 4.0.0.0-16sv)
  # SonicWall SMA 200 (10.2.1.4-31sv)
  # SonicWall SMA 210 (10.2.1.3-27sv)
  # SonicWall SMA 410 (10.2.1.5-34sv)
  # SonicWall SMA 500v for ESXi (10.2.1.3-27sv)
  # SonicWall SMA 500v for Hyper-V (10.2.1.4-31sv)
  vers = eregmatch( string:sysdesc,
                    pattern:"(Dell )?SonicWALL (S[RM]A|SSL-VPN) ([0-9]+v?)( for [^ ]+)? \(([A-Z ]+)?([^0-9]+)?([0-9.]+[^)]+)", icase:TRUE );

  if( ! isnull( vers[7] ) )
    version = vers[7];

  if( ! isnull( vers[3] ) )
    series = vers[3];
}

if( product == "unknown" || series == "unknown" ) {
  if( mod ) {
    if( mod == "EX-Virtual" ) {
      series = "Virtual Appliance";
    } else {
      # SMA 410
      buf = split( mod, sep:" ", keep:FALSE );
      if( ! isnull( buf[0] ) )
        series = buf[0];

      if( ! isnull( buf[1] ) )
        product = chomp( buf[1] );
    }

    concluded += '\n    Series/Model concluded from "' + mod + '" from OID: ' + mod_oid;
  }
}

if( version == "unknown" ) {
  sw_oid = "1.3.6.1.4.1.8741.2.1.1.3.0";
  if( vers = snmp_get( port:port, oid:sw_oid ) ) {
    # 10.2.1.8-53sv
    version = vers;
    concluded += '\n    Version concluded from "' + vers + '" from OID: ' + sw_oid;
  }
}

set_kb_item( name:"sonicwall/sra_sma/snmp/" + port + "/product", value:product );
set_kb_item( name:"sonicwall/sra_sma/snmp/" + port + "/series", value:series );
set_kb_item( name:"sonicwall/sra_sma/snmp/" + port + "/version", value:version );
set_kb_item( name:"sonicwall/sra_sma/snmp/" + port + "/concluded", value:concluded );

exit( 0 );
