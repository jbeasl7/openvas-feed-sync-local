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
  script_oid("1.3.6.1.4.1.25623.1.0.805190");
  script_version("2021-10-21T13:57:32+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-21 13:57:32 +0000 (Thu, 21 Oct 2021)");
  script_tag(name:"creation_date", value:"2015-05-27 15:15:40 +0530 (Wed, 27 May 2015)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ZOHO ManageEngine AssetExplorer Multiple Vulnerabilities");

  script_tag(name:"summary", value:"ManageEngine AssetExplorer is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to the HTTP requests to
  AssetListView.do do not require multiple steps, explicit confirmation,
  or a unique token when performing certain sensitive actions.");

  script_tag(name:"impact", value:"Successful exploitation is by tricking a
  user into following a specially crafted link, a context-dependent attacker
  can perform a Cross-Site Request Forgery (CSRF / XSRF) attack causing the
  victim to create or update asset details or conduct stored XSS attacks.");

  script_tag(name:"affected", value:"ManageEngine AssetExplorer version before 6.1.12 Build: 6112.");

  script_tag(name:"solution", value:"Update to version 6.1.12 Build 6112 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/131805");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/535473");
  script_xref(name:"URL", value:"https://www.manageengine.com/products/asset-explorer/sp-readme.html");
  script_xref(name:"URL", value:"http://www.247webhost365.co.uk/csrfxss-in-manage-engine-asset-explorer");

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

if( version_is_less( version:version, test_version:"6.1.12b6112" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.1.12 (Build 6112)", install_path:path );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
