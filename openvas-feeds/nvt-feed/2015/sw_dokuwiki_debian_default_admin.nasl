# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:dokuwiki:dokuwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111044");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-10-30 09:00:00 +0100 (Fri, 30 Oct 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Dokuwiki Default Credentials on Debian (HTTP)");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_dokuwiki_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dokuwiki/installed");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Detection of Dokuwiki default admin credentials on Debian based
  installations.");

  script_tag(name:"vuldetect", value:"Check if it is possible to login with default admin credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information.");

  script_tag(name:"insight", value:"It was possible to login with default credentials:
  admin/fix-your-debconf-settings

  This default credentials are created if Dokuwiki is installed on Debian with debconf configured to
  skip high priority questions.");

  script_tag(name:"solution", value:"Change the password of the 'admin' account.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/doku.php?id=start&do=login";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

cookie1 = eregmatch( pattern:"DokuWiki=([0-9a-z]+);", string:res );
if( isnull( cookie1[1] ) )
  exit( 0 );

sectok = eregmatch( pattern:"sectok=([0-9a-z]+)", string:res );
if( isnull( sectok[1] ) )
  exit( 0 );

host = http_host_name( port:port );

url = dir + "/doku.php?id=start&do=login&sectok=" + sectok[1];
useragent = http_get_user_agent();
data = "sectok=" + sectok[1] + "&id=start&do=login&u=admin&p=fix-your-debconf-settings";
len = strlen( data );

req = 'POST ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Referer: http://' + host + url + '\r\n' +
      'Cookie: DokuWiki=' + cookie1[1] + '\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      data;
res = http_keepalive_send_recv( port:port, data:req );

cookie2 = eregmatch( pattern:"DW([0-9a-z]+)=([0-9a-zA-Z%]+);", string:res );
if( isnull( cookie2[1] ) )
  exit( 0 );

req = 'GET ' + dir + '/doku.php?id=start HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Referer: http://' + host + url + '\r\n' +
      'Cookie: DokuWiki=' + cookie1[1] + '; DW' + cookie2[1] + '=' + cookie2[2] + '\r\n' +
      '\r\n';
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "do=admin" >< res && "action admin" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
