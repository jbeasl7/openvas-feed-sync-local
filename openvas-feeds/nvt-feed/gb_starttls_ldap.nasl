# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105016");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-25 15:18:02 +0100 (Fri, 25 Apr 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: LDAP 'Start TLS OID' Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);
  script_mandatory_keys("ldap/detected");

  script_tag(name:"summary", value:"Checks if the remote LDAP server supports SSL/TLS with the 'Start TLS' OID.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc2830");

  exit(0);
}

include("port_service_func.inc");
include("ldap.inc");

port = ldap_get_port( default:389 );

if( get_port_transport( port ) > ENCAPS_IP )
  exit( 0 );

if( ldap_starttls_supported( port:port ) ) {
  set_kb_item( name:"ldap/" + port + "/starttls", value:TRUE );
  set_kb_item( name:"starttls_typ/" + port, value:"ldap" );
  log_message( port:port, data:"The remote LDAP server supports SSL/TLS with the 'Start TLS' OID." );
}

exit( 0 );
