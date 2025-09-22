# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112687");
  script_version("2020-03-18T09:01:42+0000");
  script_tag(name:"last_modification", value:"2020-03-18 09:01:42 +0000 (Wed, 18 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-01-14 12:34:05 +0000 (Tue, 14 Jan 2020)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-5289");

  script_name("Huawei GaussDB 100 OLTP: Out-of-bounds Read Vulnerability (huawei-sa-20190925-01-database)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_gaussdb_consolidation.nasl");
  script_mandatory_keys("huawei/gaussdb/detected");

  script_tag(name:"summary", value:"There is an out-of-bounds read vulnerability in the Huawei GaussDB 100 OLTP database
  due to the insufficient checks of the specific packet length.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Attackers can construct invalid packets to attack the active and standby communication channels.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability could allow the attacker to crash the database on the standby node.");

  script_tag(name:"affected", value:"Huawei GaussDB 100 OLTP versions:

  - V300R001C00SPC100

  - V300R001C00SPC200

  - V300R001C00SPC201");

  script_tag(name:"solution", value:"Update Huawei GaussDB 100 OLTP to version V300R001C00SPC202 to fix the issue.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20190925-01-database-en");

  exit(0);
}

CPE = "cpe:/a:huawei:gaussdb_100_oltp";

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version =~ "v300r001c00spc[12]00" || version == "v300r001c00spc201" ) {
  report = report_fixed_ver( installed_version:toupper( version ), fixed_version:"V300R001C00SPC202", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
