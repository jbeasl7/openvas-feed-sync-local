# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:sitracker:support_incident_tracker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902703");
  script_version("2022-05-25T10:52:06+0000");
  script_tag(name:"last_modification", value:"2022-05-25 10:52:06 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Support Incident Tracker SiT! < 3.64 Multiple SQLi Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_support_incident_tracker_http_detect.nasl");
  script_mandatory_keys("sit/detected");

  script_tag(name:"summary", value:"Support Incident Tracker is prone to multiple SQL injection
  (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to improper input validation in 'tasks.php',
  'report_marketing.php', 'search.php' and 'billable_incidents.php' scripts via various parameters
  before being used in a SQL query.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL
  queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Support Incident Tracker version 3.63.p1 and prior.");

  script_tag(name:"solution", value:"Update to version 3.64 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/518999");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48896");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103442/PT-2011-25.txt");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( !infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit(0);

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"3.64" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.64", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
