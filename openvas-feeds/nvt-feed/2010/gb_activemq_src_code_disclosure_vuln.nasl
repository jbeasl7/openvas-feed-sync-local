# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:activemq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901110");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_cve_id("CVE-2010-1587");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Apache ActiveMQ Source Code Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_consolidation.nasl");
  script_require_ports("Services/www", 8161);
  script_mandatory_keys("apache/activemq/detected");

  script_xref(name:"URL", value:"https://issues.apache.org/activemq/browse/AMQ-2700");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39636");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/510896");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to view the source code of
  a visited page which can be used for further attacks.");

  script_tag(name:"affected", value:"Apache ActiveMQ 5.3.1 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of URL. Adding '//' after the
  port in an URL causes it to disclose the JSP page source.");

  script_tag(name:"summary", value:"Apache ActiveMQ is prone to source code information disclosure vulnerability.");

  script_tag(name:"solution", value:"Upgrade to the latest version of ActiveMQ 5.4.0 SNAPSHOT or later.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = string("//admin/queues.jsp");
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( '${sessionScope["secret"]}' >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
