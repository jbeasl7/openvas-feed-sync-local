# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805020");
  script_version("2021-10-14T06:56:37+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-10-14 06:56:37 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"creation_date", value:"2014-11-28 20:01:16 +0530 (Fri, 28 Nov 2014)");

  script_cve_id("CVE-2014-0095");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat 8.x < 8.0.4 AJP DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in
  java/org/apache/coyote/ajp/AbstractAjpProcessor.java");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial of service (thread consumption) by using a 'Content-Length: 0' AJP request to trigger a
  hang in request processing.");

  script_tag(name:"affected", value:"Apache Tomcat version 8.x before 8.0.4.");

  script_tag(name:"solution", value:"Update to version 8.0.4 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59732");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21678231");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"8.0.0.rc2", test_version2:"8.0.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.0.4", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
