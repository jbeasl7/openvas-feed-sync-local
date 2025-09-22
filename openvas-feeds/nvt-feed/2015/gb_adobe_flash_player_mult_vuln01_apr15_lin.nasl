# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805466");
  script_version("2024-07-17T05:05:38+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-3044", "CVE-2015-3043", "CVE-2015-3042", "CVE-2015-3041",
                "CVE-2015-3040", "CVE-2015-3039", "CVE-2015-3038", "CVE-2015-0360",
                "CVE-2015-0359", "CVE-2015-0357", "CVE-2015-0356", "CVE-2015-0355",
                "CVE-2015-0354", "CVE-2015-0353", "CVE-2015-0352", "CVE-2015-0351",
                "CVE-2015-0350", "CVE-2015-0349", "CVE-2015-0348", "CVE-2015-0347",
                "CVE-2015-0346", "CVE-2015-0358");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:34:42 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-04-20 14:39:25 +0530 (Mon, 20 Apr 2015)");
  script_name("Adobe Flash Player Multiple Vulnerabilities - 01 (Apr 2015) - Linux");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple unspecified use-after-free errors.

  - Multiple unspecified double free vulnerabilities.

  - An overflow condition that is triggered as user-supplied input is not
  properly validated.

  - Improper restriction of discovery of memory addresses.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service, execute arbitrary code, bypass the ASLR
  protection mechanism via unspecified vectors and allow local users to gain
  privileges.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  11.2.202.457 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  11.2.202.457 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-06.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74065");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74062");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74068");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74064");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74067");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74066");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74069");
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

if(version_is_less(version:playerVer, test_version:"11.2.202.457"))
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:     ' + "11.2.202.457" + '\n';
  security_message(data:report);
  exit(0);
}
