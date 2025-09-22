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
  script_oid("1.3.6.1.4.1.25623.1.0.112698");
  script_version("2020-02-19T08:06:16+0000");
  script_tag(name:"last_modification", value:"2020-02-19 08:06:16 +0000 (Wed, 19 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-19 07:41:05 +0000 (Wed, 19 Feb 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-1790", "CVE-2020-1811", "CVE-2020-1853");

  script_name("Huawei GaussDB 200 OLAP 6.5.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_gaussdb_consolidation.nasl");
  script_mandatory_keys("huawei/gaussdb/detected");

  script_tag(name:"summary", value:"Huawei GaussDB 200 is affected by multiple command injection and path traversal vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - multiple command injection vulnerabilities due to insufficient input validation (CVE-2020-1790, CVE-2020-1811)

  - a path traversal vulnerability due to insufficient input path validation (CVE-2020-1853)");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities could allow an
  authenticated attacker to traverse directories and download files to a specific directory which causes
  information leakage, or to inject and execute commands on the target.");

  script_tag(name:"affected", value:"Huawei GaussDB 200 OLAP version 6.5.1.");

  script_tag(name:"solution", value:"Update Huawei GaussDB 200 OLAP to version 6.5.1.1 to fix the issue.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200120-01-gaussdb200-en");
  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200120-01-path-en");
  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200122-01-gauss-en");

  exit(0);
}

CPE = "cpe:/a:huawei:gaussdb_200_olap";

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_equal( version:version, test_version:"6.5.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.5.1.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
