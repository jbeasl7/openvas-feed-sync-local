# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103190");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-07-15 13:32:07 +0200 (Fri, 15 Jul 2011)");
  script_cve_id("CVE-1999-0524");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("ICMP Timestamp Reply Information Disclosure");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("host_alive_detection.nasl", "os_fingerprint.nasl", "global_settings.nasl");
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6", "ICMPv4/TimestampRequest/failed");

  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc792");
  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc2780");

  script_tag(name:"summary", value:"The remote host responded to an ICMP timestamp request.");

  script_tag(name:"vuldetect", value:"Sends an ICMP Timestamp (Type 13) request and checks if a
  Timestamp Reply (Type 14) is received.");

  script_tag(name:"insight", value:"The Timestamp Reply is an ICMP message which replies to a
  Timestamp message. It consists of the originating timestamp sent by the sender of the Timestamp as
  well as a receive timestamp and a transmit timestamp.");

  script_tag(name:"impact", value:"This information could theoretically be used to exploit weak
  time-based random number generators in other services.");

  script_tag(name:"solution", value:"Various mitigations are possible:

  - Disable the support for ICMP timestamp on the remote host completely

  - Protect the remote host by a firewall, and block ICMP packets passing through the firewall in
  either direction (either completely or only for untrusted networks)");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

if( TARGET_IS_IPV6() )
  exit( 0 );

if( islocalhost() )
  exit( 0 );

if( get_kb_item( "ICMPv4/TimestampRequest/failed" ) )
  exit( 0 );

host = this_host();

ip = forge_ip_packet( ip_hl:5, ip_v:4, ip_off:0, ip_id:9, ip_tos:0, ip_p:IPPROTO_ICMP, ip_len:20, ip_src:host, ip_ttl:255 );
icmp = forge_icmp_packet( ip:ip, icmp_type:13, icmp_code:0, icmp_seq:1, icmp_id:1 );

filter = string( "icmp and src host ", get_host_ip(), " and dst host ", host, " and icmp[0:1] = 14" );

for( i = 0; i < 5; i++ ) {

  res = send_packet( icmp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1 );

  if( res ) {
    type = get_icmp_element( icmp:res, element:"icmp_type" );
    code = get_icmp_element( icmp:res, element:"icmp_code" );
    if( type == 14 && code == 0 ) {
      report = "The following response / ICMP packet has been received:";
      report += '\n- ICMP Type: ' + type;
      report += '\n- ICMP Code: ' + code;
      security_message( port:0, data:report, protocol:"icmp" );
      exit( 0 );
    }
  }
}

exit( 99 );
