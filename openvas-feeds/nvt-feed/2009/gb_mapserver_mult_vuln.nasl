# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800548");
  script_version("2022-11-29T10:12:26+0000");
  script_tag(name:"last_modification", value:"2022-11-29 10:12:26 +0000 (Tue, 29 Nov 2022)");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2009-0840", "CVE-2009-0839", "CVE-2009-0841", "CVE-2009-1176",
                "CVE-2009-1177", "CVE-2009-0843", "CVE-2009-0842");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MapServer < 4.10.4, 5.x < 5.2.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mapserver_http_detect.nasl");
  script_mandatory_keys("mapserver/detected");

  script_tag(name:"summary", value:"MapServer is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Heap-based buffer underflow in the readPostBody function in cgiutil.c due to a negative value
  in the Content-Length HTTP header.

  - Stack-based buffer overflow in mapserv.c in mapserv while map with a long IMAGEPATH or NAME
  attribute via a crafted id parameter in a query action.

  - Directory traversal in mapserv.c in mapserv via a .. (dot dot) in the id parameter while
  running on Windows with Cygwin.

  - Buffer overflow in mapserv.c in mapserv does not ensure that the string holding an id parameter
  ends in a '\0' character.

  - Multiple stack-based buffer overflows in maptemplate.c in mapserv.

  - Different error messages are generated when a non existent file pathname is passed in the
  queryfile parameter inside the msLoadQuery function in mapserv.

  - Display of partial file contents within an error message is triggered while attempting to read
  arbitrary invalid .map files via a full pathname in the map parameter in mapserv.");

  script_tag(name:"impact", value:"Successful exploitation will let attacker execute arbitrary code
  in the context of an affected web application and other such attacks such as, directory
  traversal, buffer overflow, and denial of service.");

  script_tag(name:"affected", value:"MapServer version 4.x before 4.10.4 and 5.x before 5.2.2 on
  all platforms.");

  script_tag(name:"solution", value:"Update to version 4.10.4, 5.2.2 or later.");

  script_xref(name:"URL", value:"http://trac.osgeo.org/mapserver/ticket/2939");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34306");
  script_xref(name:"URL", value:"http://trac.osgeo.org/mapserver/ticket/2941");
  script_xref(name:"URL", value:"http://trac.osgeo.org/mapserver/ticket/2942");
  script_xref(name:"URL", value:"http://trac.osgeo.org/mapserver/ticket/2943");
  script_xref(name:"URL", value:"http://trac.osgeo.org/mapserver/ticket/2944");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Mar/1021952.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"4.0", test_version2:"4.10.3" ) ||
    version_in_range( version:vers, test_version:"5.0", test_version2:"5.2.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.10.4/5.2.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
