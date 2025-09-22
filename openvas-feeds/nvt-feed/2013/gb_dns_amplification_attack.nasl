# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103718");
  script_version("2025-07-11T05:42:17+0000");
  script_cve_id("CVE-2006-0987");
  script_tag(name:"last_modification", value:"2025-07-11 05:42:17 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2013-05-28 11:31:19 +0200 (Tue, 28 May 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("DNS Amplification Attacks (UDP)");
  # nb: Just a standard DNS query so no ACT_ATTACK required...
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("dns_server.nasl", "global_settings.nasl");
  script_require_udp_ports("Services/udp/domain", 53);
  script_mandatory_keys("dns/server/udp/detected", "keys/is_public_addr");

  script_xref(name:"URL", value:"http://www.us-cert.gov/ncas/alerts/TA13-088A");
  script_xref(name:"URL", value:"http://www.isotf.org/news/DNS-Amplification-Attacks.pdf");

  script_tag(name:"summary", value:"A misconfigured Domain Name System (DNS) server can be exploited
  to participate in a Distributed Denial of Service (DDoS) attack.");

  script_tag(name:"vuldetect", value:"Sends a crafted UDP based DNS request and checks the response.

  Note:

  This VT is only reporting a vulnerability if the target system / service is accessible from a
  public WAN (Internet) / public LAN.

  A configuration option 'Network type' to define if a scanned network should be seen as a public
  LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"insight", value:"A Domain Name Server (DNS) Amplification attack is a popular
  form of Distributed Denial of Service (DDoS) that relies on the use of publicly accessible open
  recursive DNS servers to overwhelm a victim system with DNS response traffic.

  The basic attack technique consists of an attacker sending a DNS name lookup request to an open
  recursive DNS server with the source address spoofed to be the victim's address. When the DNS
  server sends the DNS record response, it is sent instead to the victim. Attackers will typically
  submit a request for as much zone information as possible to maximize the amplification effect.
  Because the size of the response is typically considerably larger than the request, the attacker
  is able to amplify the volume of traffic directed at the victim. By leveraging a botnet to perform
  additional spoofed DNS queries, an attacker can produce an overwhelming amount of traffic with
  little effort. Additionally, because the responses are legitimate data coming from valid servers,
  it is especially difficult to block these types of attacks.

  Note: This finding might be an acceptable risk if you:

  - trust all clients which can reach the server

  - do not allow recursive queries from outside your trusted client network");

  script_tag(name:"solution", value:"There are multiple possible mitigation steps depending on
  location and functionality needed by the DNS server:

  - Disable recursion

  - Don't allow public access to DNS Servers doing recursion

  - Leave recursion enabled if the DNS Server stays on a corporate network that cannot be reached
  by untrusted clients");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("network_func.inc");
include("port_service_func.inc");
include("host_details.inc");

if( ! is_public_addr() )
  exit( 0 );

port = service_get_port( default:53, proto:"domain", ipproto:"udp" );

if( ! soc = open_sock_udp( port ) )
  exit( 0 );

data = raw_string( 0x80, 0xa5, # Transaction ID
                   0x00, 0x10, # Flags: Standard query
                   0x00, 0x01, # Questions: 1
                   0x00, 0x00, # Answer RRs: 0
                   0x00, 0x00, # Authority RRs: 0
                   0x00, 0x00, # Additional RRs: 0
                   0x00,       # Name: <Root>
                   0x00, 0x02, # Type: NS (2) (authoritative Name Server)
                   0x00, 0x01  # Class: IN
                 );
req_len = strlen( data );

send( socket:soc, data:data );
buf = recv( socket:soc, length:4096 );
close( soc );

resp_len = strlen( buf );
if( buf && resp_len > ( 2 * req_len ) ) {

  # nb:
  # - Store the reference from this one to dns_server.nasl to show a cross-reference within the
  #   reports
  # - We don't want to / can't use get_app_* functions and we're only interested in the
  #   cross-reference here
  register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.100069" ); # dns_server.nasl
  register_host_detail( name:"detected_at", value:port + "/udp" );

  data = 'We have sent a DNS request of ' + req_len + ' bytes and received a response of ' + resp_len + ' bytes.';
  security_message( port:port, data:data, proto:"udp" );
  exit( 0 );
}

exit( 99 );
