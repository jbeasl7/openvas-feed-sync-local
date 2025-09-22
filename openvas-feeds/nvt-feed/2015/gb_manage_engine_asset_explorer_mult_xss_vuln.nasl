# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:zohocorp:manageengine_assetexplorer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805707");
  script_version("2021-10-21T13:57:32+0000");
  script_cve_id("CVE-2015-5061", "CVE-2015-2169");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-21 13:57:32 +0000 (Thu, 21 Oct 2021)");
  script_tag(name:"creation_date", value:"2015-06-24 14:40:38 +0530 (Wed, 24 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ZOHO ManageEngine AssetExplorer Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"ManageEngine AssetExplorer is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The 'VendorDef.do' script does not validate input to vendor name field before returning it to users.

  - Publisher registry entry script does not validate input before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to create a specially crafted request that would execute arbitrary
  script code in a user's browser session within the trust relationship between
  their browser and the server.");

  script_tag(name:"affected", value:"ManageEngine AssetExplorer version 6.1.12 (Build 6112) and prior.");

  script_tag(name:"solution", value:"Upgrade to ManageEngine AssetExplorer version 6.1.13 (Build 6113) or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jun/60");
  script_xref(name:"URL", value:"http://www.vulnerability-lab.com/get_content.php?id=1488");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_assetexplorer_consolidation.nasl");
  script_mandatory_keys("manageengine/assetexplorer/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_is_less( version:version, test_version:"6.1.13b6113" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.1.13 (Build 6113)", install_path:path );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
