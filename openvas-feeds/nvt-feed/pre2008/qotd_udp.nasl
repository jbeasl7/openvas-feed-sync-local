# SPDX-FileCopyrightText: 1999 Mathieu Perrin
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108029");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-1999-0103");
  script_name("Check for Quote of the Day (qotd) Service (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 1999 Mathieu Perrin");
  script_family("Useless services");
  script_dependencies("gb_qotd_detect_udp.nasl");
  script_mandatory_keys("qotd/udp/detected");

  script_tag(name:"summary", value:"The Quote of the Day (qotd) service is running on this host.");

  script_tag(name:"insight", value:"A server listens for UDP datagrams on UDP port 17. When a
  datagram is received, an answering datagram is sent containing a quote (the data in the received
  datagram is ignored).

  Remark: NIST don't see 'configuration issues' as software flaws so the referenced CVE has a
  severity of 0.0. The severity of this VT has been raised by Greenbone to still report a
  configuration issue on the target.");

  script_tag(name:"solution", value:"- Under Unix systems, comment out the 'qotd' line in
  /etc/inetd.conf and restart the inetd process

  - Under Windows systems, set the following registry keys to 0 :

  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpQotd

  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpQotd

  Then launch cmd.exe and type :

  net stop simptcp

  net start simptcp

  To restart the service.");

  script_tag(name:"impact", value:"An easy attack is 'pingpong' which IP spoofs a packet between two
  machines running qotd. This will cause them to spew characters at each other, slowing the machines
  down and saturating the network.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port( default:17, proto:"qotd", ipproto:"udp" );

if( get_kb_item( "qotd/udp/" + port + "/detected" ) ) {
  security_message( port:port, proto:"udp" );
  exit( 0 );
}

exit( 99 );