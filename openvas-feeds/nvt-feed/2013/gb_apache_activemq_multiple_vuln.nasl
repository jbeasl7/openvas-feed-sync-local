# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:activemq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903306");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-6092", "CVE-2012-6551", "CVE-2013-3060");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-04-27 12:08:18 +0530 (Sat, 27 Apr 2013)");

  script_name("Apache ActiveMQ Multiple Vulnerabilities");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_consolidation.nasl");
  script_require_ports("Services/www", 8161);
  script_mandatory_keys("apache/activemq/detected");

  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/AMQ-4124");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59401");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59402");
  script_xref(name:"URL", value:"http://activemq.apache.org/activemq-580-release.html");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/secure/ReleaseNote.jspa?projectId=12311210&version=12323282");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site
  and obtain sensitive information or cause a denial of service.");

  script_tag(name:"affected", value:"Apache ActiveMQ before 5.8.0.");

  script_tag(name:"insight", value:"- Flaw is due to an improper sanitation of user supplied input to the
    webapp/websocket/chat.js and PortfolioPublishServlet.java scripts via
    'refresh' and 'subscribe message' parameters

  - Flaw is due to the web console not requiring any form of authentication
    for access.

  - Improper sanitation of HTTP request by the sample web applications in
    the out of box broker when it is enabled.");

  script_tag(name:"solution", value:"Upgrade to version 5.8.0 or later.");

  script_tag(name:"summary", value:"Apache ActiveMQ is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) ) # nb: To have a reference to the Detection-VT
  exit( 0 );

url = "/demo/portfolioPublish?refresh=<script>alert(document.cookie)</script>&stocks=XSS-Test";

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\)</script>", extra_check:">Published <" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
