# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804063");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2014-0491", "CVE-2014-0492");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-01-21 10:42:12 +0530 (Tue, 21 Jan 2014)");
  script_name("Adobe Flash Player Security Bypass Vulnerability (Jan 2014) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56267");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64807");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64810");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-02.html");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to an unspecified error and other additional weakness.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to, bypass certain security
  restrictions and disclose certain memory information.");

  script_tag(name:"affected", value:"Adobe Flash Player version before 11.7.700.260, 11.8.x, 11.9.x before
  12.0.0.38 on Windows.");

  script_tag(name:"solution", value:"Update to Adobe Flash Player version 11.7.700.260 or 12.0.0.38 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"11.7.700.260" ) ||
   version_in_range( version:vers, test_version:"11.8.0", test_version2:"12.0.0.37" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"11.7.700.260 or 12.0.0.38 or later", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
