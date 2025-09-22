# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100082");
  script_version("2023-07-12T05:05:05+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:05 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-27 12:39:47 +0100 (Fri, 27 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("LDAP Service Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  # The LDAP Detection is currently quite fragile so using find_service6.nasl which pulls in all
  # other find_service* ones catch the most common services before.
  script_dependencies("find_service6.nasl");
  script_require_ports("Services/unknown", 389);

  script_tag(name:"summary", value:"TCP based detection of services supporting the Lightweight
  Directory Access Protocol (LDAP).");

  script_tag(name:"insight", value:"The Lightweight Directory Access Protocol, or LDAP is an
  application protocol for querying and modifying directory services running over TCP/IP.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("ldap.inc");

port = unknownservice_get_port( default:389 );

if( ldap_alive( port:port ) ) {
  service_register( port:port, proto:"ldap" );
  set_kb_item( name:"ldap/detected", value:TRUE );
  if( ldap_is_v3( port:port ) )
    report = "The LDAP Server supports LDAPv3.";
  log_message( port:port, data:report );
}

exit( 0 );
