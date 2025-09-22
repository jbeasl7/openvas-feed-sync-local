# SPDX-FileCopyrightText: 1999 Mathieu Perrin
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10198");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-1999-0103");
  script_name("Check for Quote of the Day (qotd) Service (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 1999 Mathieu Perrin");
  script_family("Useless services");
  script_dependencies("gb_qotd_detect_tcp.nasl");
  script_mandatory_keys("qotd/tcp/detected");

  script_tag(name:"summary", value:"The Quote of the Day (qotd) service is running on this host.");

  script_tag(name:"insight", value:"A server listens for TCP connections on TCP port 17. Once a
  connection is established a short message is sent out the connection (and any data received is
  thrown away). The service closes the connection after sending the quote.

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

port = service_get_port( default:17, proto:"qotd" );

if( get_kb_item( "qotd/tcp/" + port + "/detected" ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );