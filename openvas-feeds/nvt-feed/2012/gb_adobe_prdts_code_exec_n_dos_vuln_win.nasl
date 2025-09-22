# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903014");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2012-0772", "CVE-2012-0773", "CVE-2012-0724", "CVE-2012-0725");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-03-30 11:21:49 +0530 (Fri, 30 Mar 2012)");
  script_name("Adobe Flash Player Code Execution and DoS Vulnerabilities - Windows");


  script_tag(name:"summary", value:"Adobe Flash Player is prone to code execution and denial of service vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 10.3.183.18 or 11.2.202.228 or later.");
  script_tag(name:"insight", value:"The flaws are due to

  - An error within an ActiveX Control when checking the URL security domain.

  - An unspecified error within the NetStream class.");
  script_tag(name:"affected", value:"Adobe Flash Player version prior to 10.3.183.18 and 11.x to 11.1.102.63
on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
code or cause a denial of service (memory corruption) via unknown vectors.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48623");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52748");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52914");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52916");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026859");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"10.3.183.18" ) ||
    version_in_range( version:vers, test_version:"11.0", test_version2:"11.1.102.63" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.3.183.18 or 11.2.202.228", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
