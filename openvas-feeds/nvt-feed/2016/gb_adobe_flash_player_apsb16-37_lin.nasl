# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809469");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2016-7857", "CVE-2016-7858", "CVE-2016-7859", "CVE-2016-7860",
                "CVE-2016-7861", "CVE-2016-7862", "CVE-2016-7863", "CVE-2016-7864",
                "CVE-2016-7865");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-16 17:12:00 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2016-11-09 11:25:09 +0530 (Wed, 09 Nov 2016)");
  script_name("Adobe Flash Player Security Updates (APSB16-37) - Linux");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A type confusion vulnerabilities.

  - An use-after-free vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to take control of the
  affected system, and lead to code execution.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  11.2.202.644 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  11.2.202.644 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-37.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94153");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_is_less(version:playerVer, test_version:"11.2.202.644"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"11.2.202.644");
  security_message(data:report);
  exit(0);
}

