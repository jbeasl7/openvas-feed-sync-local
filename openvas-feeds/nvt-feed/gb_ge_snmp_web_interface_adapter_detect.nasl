# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807076");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-03-01 14:45:32 +0530 (Tue, 01 Mar 2016)");
  script_name("GE SNMP/Web Interface Adapter Version Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/ge/snmp_web_iface_adapter/detected");

  script_tag(name:"summary", value:"Detection of installed version
  of SNMP/Web Adapter.

  The script performs Telnet based detection of SNMP/Web Adapter");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");
include("cpe.inc");
include("host_details.inc");

port = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );

if( banner && banner =~ "GE.*SNMP/Web Interface" && "UPS" >< banner ) {

  version = "unknown";
  install = "/";

  ver = eregmatch( pattern:'SNMP/Web Interface Ver.([0-9.]+)', string:banner );
  if( ver[1] ) version = ver[1];

  set_kb_item( name:"SNMP/Web/Adapter/telnet/version", value:version );
  set_kb_item( name:"SNMP/Web/Adapter/Installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ge:ups_snmp_web_adapter_firmware:" );
  if( ! cpe )
    cpe = "cpe:/a:ge:ups_snmp_web_adapter_firmware";

  register_product( cpe:cpe, location:install, port:port, service:"telnet" );

  log_message( data:build_detection_report( app:"SNMP/Web Adapter",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:ver[0] ),
                                            port:port );
}

exit( 0 );
