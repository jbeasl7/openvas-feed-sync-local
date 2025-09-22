# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803323");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-03-04 18:17:51 +0530 (Mon, 04 Mar 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-19 19:51:57 +0000 (Thu, 19 Sep 2024)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0648", "CVE-2013-0643", "CVE-2013-0504");
  script_name("Adobe Flash Player Multiple Vulnerabilities -01 (Mar 2013) - Windows");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028210");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58184");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58185");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58186");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52374");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-08.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or cause  denial-of-service condition.");
  script_tag(name:"affected", value:"Adobe Flash Player 10.3.183.63 and earlier, and 11.x to 11.6.602.168 on
  Windows");
  script_tag(name:"insight", value:"Multiple flaws due to:

  - A flaw in the ExternalInterface ActionScript feature.

  - Firefox sandbox does not restrict privileges.

  - Buffer overflow in the Flash Player broker service.");
  script_tag(name:"solution", value:"Update to version 10.3.183.67 or 11.6.602.171.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"10.3.183.63") ||
    version_in_range( version:vers, test_version:"11.0", test_version2:"11.6.602.168" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.3.183.67 or 11.6.602.171", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
