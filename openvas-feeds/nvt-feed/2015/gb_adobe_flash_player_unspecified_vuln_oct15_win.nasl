# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806098");
  script_version("2024-07-17T05:05:38+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-7645", "CVE-2015-7647", "CVE-2015-7648");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:34:02 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-10-16 15:53:08 +0530 (Fri, 16 Oct 2015)");
  script_name("Adobe Flash Player Unspecified Vulnerability (Oct 2015) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to some unspecified
  critical vulnerabilities in Adobe Flash Player.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a crash and potentially an attacker to take control of the affected
  system.");

  script_tag(name:"affected", value:"Adobe Flash Player version 18.x through 18.0.0.252
  19.x through 19.0.0.207 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  18.0.0.255 or 19.0.0.226 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsa15-05.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-27.html");
  script_xref(name:"URL", value:"http://blog.trendmicro.com/trendlabs-security-intelligence/new-adobe-flash-zero-day-used-in-pawn-storm-campaign");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:playerVer, test_version:"19.0", test_version2:"19.0.0.207"))
{
  fix = "19.0.0.226";
  VULN = TRUE;
}

else if(version_in_range(version:playerVer, test_version:"18.0", test_version2:"18.0.0.252"))
{
  fix = "18.0.0.255";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:' + fix + '\n';
  security_message(data:report);
  exit(0);
}
