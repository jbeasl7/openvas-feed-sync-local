# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:esri:arcgis";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113041");
  script_version("2023-01-04T10:13:11+0000");
  script_tag(name:"last_modification", value:"2023-01-04 10:13:11 +0000 (Wed, 04 Jan 2023)");
  script_tag(name:"creation_date", value:"2017-10-25 13:47:48 +0200 (Wed, 25 Oct 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ArcGis Server < 10.4.1 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_arcgis_server_http_detect.nasl");
  script_mandatory_keys("arcgis/detected");

  script_tag(name:"summary", value:"ArcGIS Server is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ArcGIS sets useCodebaseOnly to false in Java, which creates a
  risk for remote code execution.");

  script_tag(name:"impact", value:"Successful exploitation could allow the attacker to execute
  arbitrary code on the host.");

  script_tag(name:"affected", value:"ArcGIS Server version 10.3.1 and prior.");

  script_tag(name:"solution", value:"Update to version 10.4.1 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Oct/18");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Oct/21");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( !port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( !version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if( version_is_less( version: version, test_version: "10.4.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.4.1" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
