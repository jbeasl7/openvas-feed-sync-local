# SPDX-FileCopyrightText: 1999 Mathieu Perrin
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10043");
  script_version("2023-09-12T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-12 05:05:19 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-1999-0103", "CVE-1999-0639");
  script_name("Check for Chargen Service (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 1999 Mathieu Perrin");
  script_family("Useless services");
  script_dependencies("gb_chargen_detect_tcp.nasl");
  script_mandatory_keys("chargen/tcp/detected");

  script_tag(name:"summary", value:"The remote host is running a 'chargen' service.");

  script_tag(name:"vuldetect", value:"Checks whether a chargen service is exposed on the target
  host.");

  script_tag(name:"insight", value:"When contacted, chargen responds with some random characters
  (something like all the characters in the alphabet in a row). When contacted via TCP, it will
  continue spewing characters until the client closes the connection.

  The purpose of this service was to mostly to test the TCP/IP protocol by itself, to make sure that
  all the packets were arriving at their destination unaltered. It is unused these days, so it is
  suggested you disable it, as an attacker may use it to set up an attack against this host, or
  against a third party host using this host as a relay.");

  script_tag(name:"solution", value:"- Under Unix systems, comment out the 'chargen' line in
  /etc/inetd.conf and restart the inetd process

  - Under Windows systems, set the following registry keys to 0 :

  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpChargen

  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpChargen

  Then launch cmd.exe and type :

  net stop simptcp

  net start simptcp

  To restart the service.");

  script_tag(name:"impact", value:"An easy attack is 'ping-pong' in which an attacker spoofs a
  packet between two machines running chargen. This will cause them to spew characters at each
  other, slowing the machines down and saturating the network.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port( default:19, proto:"chargen" );

if( get_kb_item( "chargen/tcp/" + port + "/detected" ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
