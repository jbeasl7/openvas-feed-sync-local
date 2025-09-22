# SPDX-FileCopyrightText: 2004 Cedric Tissieres, Objectif Securite
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15753");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2004-0789");
  script_name("Multiple Vendor DNS Response Flooding DoS Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2004 Cedric Tissieres, Objectif Securite");
  script_dependencies("dns_server.nasl", "global_settings.nasl");
  script_require_udp_ports("Services/udp/domain", 53);
  script_mandatory_keys("dns/server/udp/detected");
  script_exclude_keys("keys/islocalhost");

  script_xref(name:"URL", value:"https://web.archive.org/web/20041112055702/http://www.uniras.gov.uk/vuls/2004/758884/index.htm");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11642");

  script_tag(name:"insight", value:"This vulnerability results in vulnerable DNS servers entering
  into an infinite query and response message loop, leading to the consumption of network and CPU
  resources, and denying DNS service to legitimate users.");

  script_tag(name:"impact", value:"An attacker may exploit this flaw by finding two vulnerable
  servers and set up a 'ping-pong' attack between the two hosts.");

  script_tag(name:"solution", value:"Please see the reference for platform specific remediations.");

  script_tag(name:"affected", value:"Axis Communication, dnrd, Don Moore and Posadis are know
  affected vendors.");

  script_tag(name:"summary", value:"Multiple DNS vendors are reported susceptible to a denial of
  service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("port_service_func.inc");

if( islocalhost() ) exit( 0 );

port = service_get_port( default:53, proto:"domain", ipproto:"udp" );

soc = open_sock_udp ( port );
if( ! soc )
  exit( 0 );

my_data  = string( "\xf2\xe7\x81\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77" );
my_data += string( "\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00" );
my_data += string( "\x00\x01\x00\x01" );

send( socket:soc, data:my_data );
r = recv( socket:soc, length:4096 );

if( r && ( ord( r[2] ) & 0x80 ) ) {

  send( socket:soc, data:r );
  r = recv( socket:soc, length:4096 );

  if( r && ( ord( r[2] ) & 0x80 ) ) {
    close( soc );
    security_message( port:port, proto:"udp" );
    exit( 0 );
  }
}

close( soc );
exit( 99 );