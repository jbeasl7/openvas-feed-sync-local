# SPDX-FileCopyrightText: 2005 John Lampe
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10723");
  script_version("2023-07-12T05:05:05+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:05 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("LDAP allows anonymous binds");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2005 John Lampe");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);
  script_mandatory_keys("ldap/detected");

  script_tag(name:"solution", value:"Disable NULL BIND on your LDAP server.");

  script_tag(name:"summary", value:"It is possible to disclose LDAP information.");

  script_tag(name:"insight", value:"Improperly configured LDAP servers will allow
  any user to connect to the server via a NULL BIND and query for information.

  Note: NULL BIND is required for LDAPv3. Therefore this plugin will not run
  against LDAPv3 servers.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ldap.inc");
include("port_service_func.inc");

port = ldap_get_port( default:389 );

if( ldap_is_v3( port:port ) )
  exit( 99 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

string = raw_string( 0x30, 0x0C, 0x02, 0x01, 0x01, 0x60,
                     0x07, 0x02, 0x01, 0x02, 0x04, 0x00,
                     0x80, 0x80 );

send( socket:soc, data:string );
res = recv( socket:soc, length:4096 );
close( soc );
if( ! res )
  exit( 0 );

len = strlen( res );
if( len > 6 ) {
  error_code = substr( res, len - 7, len - 5 );
  if( hexstr( error_code ) == "0a0100" ) {
    security_message( port:port );
    set_kb_item( name:"LDAP/" + port + "/NULL_BIND", value:TRUE );
    exit( 0 );
  }
}

exit( 99 );
