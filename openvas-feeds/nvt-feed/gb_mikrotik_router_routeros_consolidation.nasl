# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810608");
  script_version("2025-02-28T15:40:30+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-28 15:40:30 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-03-09 15:28:48 +0530 (Thu, 09 Mar 2017)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MikroTik RouterOS Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_mikrotik_router_routeros_ftp_detect.nasl",
                      "gb_mikrotik_router_routeros_telnet_detect.nasl",
                      "gb_mikrotik_router_routeros_http_detect.nasl",
                      "gb_mikrotik_router_routeros_ssh_detect.nasl",
                      "gb_mikrotik_router_routeros_pptp_detect.nasl",
                      "gb_mikrotik_router_routeros_snmp_detect.nasl",
                      "gb_mikrotik_router_routeros_winbox_detect.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"Consolidation of MikroTik RouterOS detections.");

  script_xref(name:"URL", value:"https://mikrotik.com/software");

  exit(0);
}

if( ! get_kb_item( "mikrotik/routeros/detected" ) )
  exit( 0 );

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

location = "/";
detected_version = "unknown";

# nb: No version extraction via PPTP or SSH banner
foreach source( make_list( "snmp", "ftp", "telnet", "http", "winbox" ) ) {
  version_list = get_kb_list( "mikrotik/routeros/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe( value:detected_version, exp:"^([A-Za-z0-9.]+)", base:"cpe:/o:mikrotik:routeros:" );
if( !cpe )
  cpe = "cpe:/o:mikrotik:routeros";

os_register_and_report( os:"Mikrotik Router OS", cpe:cpe, runs_key:"unixoide",
                        desc:"MikroTik RouterOS Detection Consolidation" );

if( http_ports = get_kb_list( "mikrotik/routeros/http/port" ) ) {
  foreach port( http_ports ) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item( "mikrotik/routeros/http/" + port + "/concluded" );
    if( concluded )
      extra += "  Concluded from version/product identification result:" + concluded + '\n';

    conclUrl = get_kb_item( "mikrotik/routeros/http/" + port + "/concludedUrl" );
    if( conclUrl )
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product( cpe:cpe, location:location, port:port, service:"www" );
  }
}

if( snmp_ports = get_kb_list( "mikrotik/routeros/snmp/port" ) ) {
  foreach port( snmp_ports ) {
    extra += "SNMP on port " + port + '/udp\n';

    concluded = get_kb_item( "mikrotik/routeros/snmp/" + port + "/concluded");
    if( concluded )
      extra += concluded;

    register_product( cpe:cpe, location:location, port:port, service:"snmp", proto:"udp" );
  }
}

if( ftp_ports = get_kb_list( "mikrotik/routeros/ftp/port" ) ) {
  foreach port( ftp_ports ) {
    extra += "FTP on port " + port + '\n';

    concluded = get_kb_item( "mikrotik/routeros/ftp/" + port + "/concluded" );
    if( concluded )
      extra += "  FTP Banner: " + concluded + '\n';

    register_product( cpe:cpe, location:location, port:port, service:"ftp" );
  }
}

if( ssh_ports = get_kb_list( "mikrotik/routeros/ssh/port" ) ) {
  foreach port( ssh_ports ) {
    extra += "SSH on port: " + port + '/tcp\n';

    concluded = get_kb_item( "mikrotik/routeros/ssh/" + port + "/concluded" );
    if( concluded )
      extra += "  SSH Banner: " + concluded + '\n';

    register_product( cpe:cpe, location:location, port:port, service:"ssh" );
  }
}

if( pptp_ports = get_kb_list( "mikrotik/routeros/pptp/port" ) ) {
  foreach port( pptp_ports ) {
    extra += "PPTP on port " + port + '/tcp\n';

    concluded = get_kb_item( "mikrotik/routeros/pptp/" + port + "/concluded" );
    if( concluded )
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product( cpe:cpe, location:location, port:port, service:"pptp" );
  }
}

if( telnet_ports = get_kb_list( "mikrotik/routeros/telnet/port" ) ) {
  foreach port( telnet_ports ) {
    extra += "Telnet on port " + port + '\n';

    concluded = get_kb_item( "mikrotik/routeros/telnet/" + port + "/concluded" );
    if( concluded )
      extra += " Telnet Banner: " + concluded + '\n';

    register_product( cpe:cpe, location:location, port:port, service:"telnet" );
  }
}

if( winbox_ports = get_kb_list( "mikrotik/routeros/winbox/port" ) ) {
  foreach port( winbox_ports ) {
    extra += "Winbox on port " + port + '/tcp\n';

    concluded = get_kb_item( "mikrotik/routeros/winbox/" + port + "/concluded" );
    if( concluded )
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product( cpe:cpe, location:location, port:port, service:"winbox" );
  }
}

report = build_detection_report( app:"Mikrotik Router OS", version:detected_version, install:location,
                                 cpe:cpe );

if( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp( extra );
}

log_message( port:0, data:report );

exit( 0 );
