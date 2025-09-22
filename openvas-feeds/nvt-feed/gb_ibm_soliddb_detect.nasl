# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100721");
  script_version("2023-06-23T16:09:17+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-06-23 16:09:17 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"creation_date", value:"2010-07-21 19:56:46 +0200 (Wed, 21 Jul 2010)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("UNICOM/IBM solidDB Detection (TCP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 1315);

  script_tag(name:"summary", value:"TCP based detection of UNICOM/IBM solidDB.");

  script_xref(name:"URL", value:"https://www.teamblue.unicomsi.com/products/soliddb/");

  exit(0);
}

include("cpe.inc");
include("byte_func.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = unknownservice_get_port( default:1315 );
host = get_host_name();

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

user = "DBA";
pass = raw_string( 0x76, 0xce, 0xa5, 0x2d, 0x72, 0x4f, 0x6f, 0x02 );
tcp = string( "tcp ", host, " ", port );
vt_strings = get_vt_strings();
id = vt_strings["default"] + "(" + this_host() + ")";
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

req = raw_string( 0x02, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00 ) +
      mkdword( 1 ) + mkdword( strlen( tcp ) ) + tcp + mkdword( strlen( user ) ) +
      user + mkdword( strlen( pass ) ) + pass + mkdword( 4 ) + mkdword( 3 ) +
      mkdword( 2 ) + mkdword( 1 ) + mkdword( 1 ) + mkdword( 0 ) +
      mkdword( strlen( id ) + 3 ) + raw_string( 0x04 ) + mkword( strlen( id ) ) + id;

send( socket:soc, data:req );
ret = recv( socket:soc, length:128 );
if( ! ret || isnull( ret ) ) {
  close( soc );
  exit( 0 );
}

len = strlen( ret );

if( ( len == 35 || len >= 27 ) &&
    hexstr( substr( ret, 0, 6 ) ) == "02000100000000" &&
    hexstr( substr( ret, 6, 7 ) ) == "0001" ) {

  install = port + "/tcp";
  service_register( port:port, proto:"soliddb" );

  version_cmd = "version";
  vers = "unknown";
  a = getdword( blob:ret, pos:27 );
  b = getdword( blob:ret, pos:31 );

  req = raw_string( 0x02, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00 ) + mkdword( 2 ) + mkdword( a ) +
        mkdword( b ) + mkdword( 0x012d ) + mkdword( strlen( version_cmd ) ) + version_cmd;

  send( socket:soc, data:req );
  ret = recv( socket:soc, length:1024 );
  close( soc );

  if( "solidDB" >< ret ) {
    s = 19;
    while( l = getdword( blob:ret, pos:s ) ) {
      if( s + 4 + l < strlen( ret ) ) {
        version_string += substr( ret, s + 4, s + 4 + l - 1 );
        s += l + 4;
      } else {
        break;
      }
    }
  }

  if( version_string ) {
    version = eregmatch( pattern:"([0-9.]+).?(Build [0-9]*)?", string:version_string );
    if( ! isnull( version[1] ) ) {
      vers = version[1];
      if( ! isnull( version[2] ) ) {
        vers += " " + version[2];
      }
    }
  }

  service_register(port: port, proto: "soliddb");

  if( vers == "unknown" || isnull( vers ) ) {

    cpe = "cpe:/a:ibm:soliddb";

    set_kb_item( name:"IBM-soliddb/installed", value:TRUE );
    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"UNICOM/IBM solidDB",
                                              version:vers,
                                              install:install,
                                              cpe:cpe ),
                                              port:port );
  } else {

    set_kb_item( name:"OpenDatabase/found", value:TRUE );
    set_kb_item( name:"IBM-soliddb/installed", value:TRUE );
    set_kb_item( name:"soliddb/" + port + "/version", value:vers );

    ## if build version is required you need to use the get_kb_item() instead of get_app_version() in the VT.
    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:ibm:soliddb:" );
    if( ! cpe )
      cpe = "cpe:/a:ibm:soliddb";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"UNICOM/IBM solidDB",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              extra:"The remote solidDB has default credentials set. You should change this credentials as soon as possible.",
                                              concluded:version_string ),
                                              port:port );
  }
}

exit( 0 );
