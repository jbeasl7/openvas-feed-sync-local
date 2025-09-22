# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100339");
  script_version("2024-09-16T09:36:54+0000");
  script_tag(name:"last_modification", value:"2024-09-16 09:36:54 +0000 (Mon, 16 Sep 2024)");
  script_tag(name:"creation_date", value:"2009-11-06 12:41:10 +0100 (Fri, 06 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetIQ eDirectory Detection (LDAP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);
  script_mandatory_keys("ldap/detected");

  script_tag(name:"summary", value:"LDAP based detection NetIQ eDirectory.");

  script_xref(name:"URL", value:"https://www.netiq.com");

  exit(0);
}

include("cpe.inc");
include("dump.inc");
include("host_details.inc");
include("ldap.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ldap_get_port( default:389 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

req = raw_string( 0x30, 0x25, 0x02, 0x01,
                  0x01,                                      # messageID
                  0x63, 0x20,                                # searchRequest
                  0x04, 0x00,
                  0x0a, 0x01, 0x00,                          # scope: baseObject
                  0x0a, 0x01, 0x00,                          # derefAliases: neverDerefAliases
                  0x02, 0x01, 0x00,                          # sizeLimit: 0
                  0x02, 0x01, 0x00,                          # timeLimit: 0
                  0x01, 0x01, 0x00,                          # typesOnly: False
                  0x87, 0x0b,                                # Filter (objectClass=*)
                  "objectClass",
                  0x30, 0x00 );

if( ! res = ldap_send_recv( req:req, sock:soc ) ) {
  close( soc );
  exit( 0 );
}

close( soc );

str = bin2string( ddata:res, noprint_replacement:"#" );

if( str !~ "LDAP Agent for (Novell|NetIQ) eDirectory" && "Anonymous Simple Bind Disabled" >!< str )
  exit( 0 );

version = "unknown";
report_version = "unknown";
location = "/";

set_kb_item( name:"netiq/edirectory/detected", value:TRUE );
set_kb_item( name:"netiq/edirectory/ldap/detected", value:TRUE );

# LDAP Agent for NetIQ  eDirectory 9.0 (40002.38)
# LDAP Agent for Novell eDirectory 8.8 SP5 Patch 4 (20504.13)
# LDAP Agent for Novell eDirectory 8.8 SP2 (20216.46)
vers = eregmatch( pattern:'LDAP Agent for (Novell|NetIQ) eDirectory (([0-9.]+)( SP([0-9]+))?( Patch ([0-9]+))?( \\(([^)]+)\\)))', string:str );

if( ! isnull( vers[3] ) ) {
  version = vers[3];
  report_version = version;
}

if( ! isnull( vers[5] ) ) {
  sp = vers[5];
  set_kb_item( name:"netiq/edirectory/" + port + "/sp", value:sp );
  report_version += " SP" + sp;
}

if( ! isnull( vers[7] ) ) {
  patch = vers[7];
  set_kb_item( name:"netiq/edirectory/" + port + "/patch", value:patch );
  report_version += " Patch" + patch;
}

if( ! isnull( vers[9] ) ) {
  build = vers[9];
  set_kb_item( name:"netiq/edirectory/" + port + "/build", value:build );
  report_version += " (" + build + ")";
}

cpe1 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:netiq:edirectory:" );
cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:novell:edirectory:" );
if( ! cpe1 ) {
  cpe1 = "cpe:/a:netiq:edirectory";
  cpe2 = "cpe:/a:novell:edirectory";
}

register_product( cpe:cpe1, location:location, port:port, service:"ldap" );
register_product( cpe:cpe2, location:location, port:port, service:"ldap" );

log_message( data:build_detection_report( app:"NetIQ eDirectory", version:report_version, install:location,
                                          cpe:cpe1, concluded:vers[0] ),
             port:port );

exit( 0 );
