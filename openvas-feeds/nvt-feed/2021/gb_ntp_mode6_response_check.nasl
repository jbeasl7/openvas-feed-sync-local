# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117692");
  script_version("2025-07-11T05:42:17+0000");
  script_tag(name:"last_modification", value:"2025-07-11 05:42:17 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2021-09-24 13:00:19 +0000 (Fri, 24 Sep 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Network Time Protocol (NTP) Mode 6 Query Response Check (UDP)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_dependencies("ntp_open.nasl", "global_settings.nasl");
  script_mandatory_keys("ntp/mode6/response/received");

  script_xref(name:"URL", value:"https://scan.shadowserver.org/ntpversion/");
  script_xref(name:"URL", value:"https://www.virtuesecurity.com/kb/ntp-mode-6-vulnerabilities/");
  script_xref(name:"URL", value:"https://docs.ntpsec.org/latest/mode6.html");

  script_tag(name:"summary", value:"Services which are supporting the Network Time Protocol (NTP)
  and respond to Mode 6 queries are prone to an information disclosure and might be misused for
  Distributed Denial of Service (DDoS) attacks.");

  script_tag(name:"vuldetect", value:"Checks if the remote NTP service has responded to NTP Mode 6
  Queries.

  Note:

  This VT is only reporting a vulnerability if the target system / service is accessible from a
  public WAN (Internet) / public LAN. If the target system is on the local LAN the VT is reporting
  the issue only as a log message.

  A configuration option 'Network type' to define if a scanned network should be seen as a public
  LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"insight", value:"If a service supporting NTP is publicly accessible and is
  responding to Mode 6 queries it can participate in an Amplification-based DDoS attack or could
  disclose sensitive system information.

  - Mode 6 Information Disclosure:

  Mode 6 queries can often be used to obtain system information such as system and kernel versions.

  - Mode 6 Amplification Attacks:

  An Amplification attack is a popular form of DDoS that relies on the use of publicly accessible
  NTP services to overwhelm a victim system with response traffic.

  The basic attack technique consists of an attacker sending a valid query request to a NTP service
  with the source address spoofed to be the victim's address. When the Memcached server sends the
  response, it is sent instead to the victim. Attackers will typically first inserting records into
  the open server to maximize the amplification effect. Because the size of the response is
  typically considerably larger than the request, the attacker is able to amplify the volume of
  traffic directed at the victim. By leveraging a botnet to perform additional spoofed queries, an
  attacker can produce an overwhelming amount of traffic with little effort. Additionally, because
  the responses are legitimate data coming from valid clients, it is especially difficult to block
  these types of attacks.");

  script_tag(name:"solution", value:"The following mitigation possibilities are currently available:

  - Generally disable public access to the UDP port of this NTP service.

  - Only allow Mode 6 queries by trusted clients / networks.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("network_func.inc");
include("port_service_func.inc");
include("host_details.inc");

if( ! is_public_addr() )
  log_only = TRUE;

port = service_get_port( default:123, ipproto:"udp", proto:"ntp" );

if( ! get_kb_item( "ntp/mode6/response/" + port + "/received" ) )
  exit( 99 );

if( ! recv_data_len = get_kb_item( "ntp/mode6/response/" + port + "/recv_data_len" ) )
  exit( 99 );

if( ! sent_data_len = get_kb_item( "ntp/mode6/response/" + port + "/sent_data_len" ) )
  exit( 99 );

if( recv_data_len > ( 20 * sent_data_len ) ) {
  report = 'The remote NTP service responded on Mode 6 queries. We have sent a query request of ' +
           sent_data_len + ' bytes and received a response of ' + recv_data_len + ' bytes.';

  # nb:
  # - Store the reference from this one to ntp_open.nasl to show a cross-reference within the
  #   reports
  # - We don't want to / can't use get_app_* functions and we're only interested in the
  #   cross-reference here
  register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.10884" ); # ntp_open.nasl
  register_host_detail( name:"detected_at", value:port + "/tcp" );

  if( ! log_only ) {
    security_message( port:port, data:report, proto:"udp" );
    exit( 0 );
  } else {
    log_message( port:port, data:report, proto:"udp" );
    exit( 0 );
  }
}

exit( 99 );
