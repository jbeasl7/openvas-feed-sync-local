# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:dreamweaver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813039");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-4924");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-22 13:46:00 +0000 (Fri, 22 Jun 2018)");
  script_tag(name:"creation_date", value:"2018-03-15 11:20:29 +0530 (Thu, 15 Mar 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Dreamweaver Command Injection Vulnerability (Mar 2018) - Windows");

  script_tag(name:"summary", value:"Adobe Dreamweaver is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper
  sanitization of user supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code in the context of the current user. Failed exploit
  attempts may result in a denial of service condition.");

  script_tag(name:"affected", value:"Adobe Dreamweaver CC 18.0 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Dreamweaver CC 18.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb18-07.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103395");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_dreamweaver_detect.nasl");
  script_mandatory_keys("Adobe/Dreamweaver/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
drVer = infos["version"];
drPath = infos["location"];

if(version_is_less(version:drVer, test_version:"18.1"))
{
  report = report_fixed_ver(installed_version:drVer, fixed_version:"18.1", install_path:drPath);
  security_message(data:report);
  exit(0);
}
exit(0);
