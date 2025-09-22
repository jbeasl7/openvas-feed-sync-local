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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100725");
  script_version("2022-05-02T09:35:37+0000");
  script_cve_id("CVE-2010-1452");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-07-27 20:48:46 +0200 (Tue, 27 Jul 2010)");
  script_name("Apache HTTP Server Multiple Remote Denial of Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_mandatory_keys("apache/http_server/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41963");
  script_xref(name:"URL", value:"http://www.apache.org/dist/httpd/Announcement2.2.html");
  script_xref(name:"URL", value:"http://www.apache.org/dist/httpd/CHANGES_2.2.16");

  script_tag(name:"affected", value:"Versions prior to Apache 2.2.16 are vulnerable.");

  script_tag(name:"solution", value:"These issues have been fixed in Apache 2.2.16. Please see the
  references for more information.");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to multiple remote denial-of-service
  vulnerabilities.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to deny service to
  legitimate users.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"2.2", test_version2:"2.2.15" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.16", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
