# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805261");
  script_version("2024-07-04T05:05:37+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-0311", "CVE-2015-0312");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 17:41:45 +0000 (Tue, 02 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-01-27 16:19:35 +0530 (Tue, 27 Jan 2015)");
  script_name("Adobe Flash Player Unspecified Code Execution Vulnerability (Jan 2015) - Linux");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to unspecified arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified
  error and double-free flaw that is triggered as user-supplied input is not
  properly validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Flash Player through version
  11.2.202.438 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  11.2.202.440 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://secunia.com/advisories/62432");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72283");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72343");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsa15-01.html");
  script_xref(name:"URL", value:"http://www.rapid7.com/db/vulnerabilities/adobe-flash-apsb15-03-cve-2015-0312");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"11.2.202.440"))
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:     11.2.202.440\n';
  security_message(data:report);
  exit(0);
}
