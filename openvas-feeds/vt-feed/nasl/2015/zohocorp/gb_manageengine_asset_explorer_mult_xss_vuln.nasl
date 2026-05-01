# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zohocorp:manageengine_assetexplorer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805707");
  script_version("2026-04-22T06:16:44+0000");
  script_cve_id("CVE-2015-5061", "CVE-2015-2169");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2026-04-22 06:16:44 +0000 (Wed, 22 Apr 2026)");
  script_tag(name:"creation_date", value:"2015-06-24 14:40:38 +0530 (Wed, 24 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine AssetExplorer Multiple Cross Site Scripting Vulnerabilities");

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
  script_copyright("Copyright (C) 2015 Greenbone AG");
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
