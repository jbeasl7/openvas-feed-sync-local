# Copyright (C) 2010 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:apache:activemq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801203");
  script_version("2022-12-02T10:11:16+0000");
  script_tag(name:"last_modification", value:"2022-12-02 10:11:16 +0000 (Fri, 02 Dec 2022)");
  script_tag(name:"creation_date", value:"2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)");
  script_cve_id("CVE-2010-1244", "CVE-2010-0684");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Apache ActiveMQ Persistent Cross-Site Scripting Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_consolidation.nasl");
  script_require_ports("Services/www", 8161);
  script_mandatory_keys("apache/activemq/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57398");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39119");
  script_xref(name:"URL", value:"http://www.rajatswarup.com/CVE-2010-0684.txt");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39223");
  script_xref(name:"URL", value:"https://issues.apache.org/activemq/browse/AMQ-2625");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Apache ActiveMQ 5.3 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input via the
  'JMSDestination' parameter to createDestination.action that allows the
  attackers to insert arbitrary HTML and script code.");

  script_tag(name:"solution", value:"Upgrade to the latest version of ActiveMQ 5.3.1 or later.");

  script_tag(name:"summary", value:"Apache ActiveMQ is prone to cross-site scripting and cross-site request forgery vulnerabilities.");

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

random_value = rand();
req = http_get( item:string("/admin/createDestination.action?",
                            "JMSDestinationType=queue&JMSDestination=",
                            "VT-XSS-Test-", random_value), port:port );
res = http_keepalive_send_recv( port:port, data:req );

url = "/admin/queues.jsp";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

verify_string = string( "VT-XSS-Test-", random_value );

if( verify_string >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
