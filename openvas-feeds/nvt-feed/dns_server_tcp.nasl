# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108018");
  script_version("2025-07-11T05:42:17+0000");
  script_tag(name:"last_modification", value:"2025-07-11 05:42:17 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2009-03-22 17:08:49 +0100 (Sun, 22 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("DNS Server Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 53);

  script_tag(name:"summary", value:"TCP based detection of a DNS server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("dns_func.inc");

# query '1.0.0.127.in-addr.arpa/PTR/IN'
data = raw_string( 0xB8, 0x4C, 0x01, 0x00, 0x00, 0x01,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x01, 0x31, 0x01, 0x30, 0x01, 0x30,
                   0x03, 0x31, 0x32, 0x37, 0x07, 0x69,
                   0x6E, 0x2D, 0x61, 0x64, 0x64, 0x72,
                   0x04, 0x61, 0x72, 0x70, 0x61, 0x00,
                   0x00, 0x0C, 0x00, 0x01 );

data = raw_string( 0x00, 0x28 ) + data;

port = unknownservice_get_port( default:53 ); # nb: At least Dnsmasq allows to configure a DNS port other then 53

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

send( socket:soc, data:data );
buf = recv( socket:soc, length:4096 );
if( ! buf ) {
  close( soc );
  exit( 0 );
}

if( strlen( buf ) > 5 &&
    ord( buf[4] ) & 0x80 ) {

  # nb:
  # - Store link between this and some other VTs which might require this
  # - We don't use the host_details.inc functions in both so we need to call this directly
  register_host_detail( name:"detected_at", value:port + "/tcp" );

  set_kb_item( name:"DNS/tcp/" + port, value:TRUE );
  set_kb_item( name:"dns/server/detected", value:TRUE );
  set_kb_item( name:"dns/server/tcp/detected", value:TRUE );

  banner = dnsVersionReq( soc:soc, proto:"tcp", port:port );
  if( banner )
    report = 'The remote DNS server banner is:\n\n' + banner;
  service_register( port:port, ipproto:"tcp", proto:"domain", message:report );
  log_message( port:port, data:report, protocol:"tcp" );
  close( soc );
  exit( 0 );
}

close( soc );
exit( 0 );
