# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805270");
  script_version("2024-07-04T05:05:37+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-0313", "CVE-2015-0314", "CVE-2015-0315", "CVE-2015-0316",
                "CVE-2015-0317", "CVE-2015-0318", "CVE-2015-0319", "CVE-2015-0320",
                "CVE-2015-0321", "CVE-2015-0322", "CVE-2015-0323", "CVE-2015-0324",
                "CVE-2015-0325", "CVE-2015-0326", "CVE-2015-0327", "CVE-2015-0328",
                "CVE-2015-0329", "CVE-2015-0330", "CVE-2015-0331");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 17:41:33 +0000 (Tue, 02 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-02-10 11:05:20 +0530 (Tue, 10 Feb 2015)");
  script_name("Adobe Flash Player Multiple Vulnerabilities-01 (Feb 2015) - Linux");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple unspecified use-after-free errors.

  - Multiple unspecified errors due to improper validation of user-supplied input.

  - Multiple unspecified type confusion errors.

  - Multiple errors leading to overflow condition.

  - Multiple unspecified NULL pointer dereference errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to corrupt memory, dereference already freed memory, execute arbitrary
  code or have other unspecified impacts.");

  script_tag(name:"affected", value:"Adobe Flash Player before version
  11.2.202.442 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  11.2.202.442 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-04.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72429");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72514");

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

if(version_is_less(version:playerVer, test_version:"11.2.202.442"))
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:     ' + "11.2.202.442" + '\n';
  security_message(data:report);
  exit(0);
}
