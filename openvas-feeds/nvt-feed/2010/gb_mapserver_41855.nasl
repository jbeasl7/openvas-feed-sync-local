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

CPE = "cpe:/a:umn:mapserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100737");
  script_version("2022-11-29T10:12:26+0000");
  script_tag(name:"last_modification", value:"2022-11-29 10:12:26 +0000 (Tue, 29 Nov 2022)");
  script_tag(name:"creation_date", value:"2010-08-02 19:12:50 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2010-2539", "CVE-2010-2540");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MapServer < 4.10.6, 5.x < 5.6.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mapserver_http_detect.nasl");
  script_mandatory_keys("mapserver/detected");

  script_tag(name:"summary", value:"MapServer is prone to multiple remote vulnerabilities,
  including a buffer overflow vulnerability and an unspecified security vulnerability affecting the
  CGI command line debug arguments.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary code
  within the context of the affected application or crash the application. Other attacks are also
  possible.");

  script_tag(name:"affected", value:"MapServer prior to version 4.10.6 and 5.x prior to 5.6.4.");

  script_tag(name:"solution", value:"The vendor has released updates to address these issues.
  Please see the references for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41855");
  script_xref(name:"URL", value:"http://trac.osgeo.org/mapserver/ticket/3484");
  script_xref(name:"URL", value:"http://trac.osgeo.org/mapserver/ticket/3485");
  script_xref(name:"URL", value:"http://lists.osgeo.org/pipermail/mapserver-users/2010-July/066052.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"5.6", test_version2:"5.6.3" ) ||
    version_in_range( version:vers, test_version:"4.10", test_version2:"4.10.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.10.6/5.6.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
