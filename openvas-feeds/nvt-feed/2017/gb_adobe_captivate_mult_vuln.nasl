# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:captivate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811136");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-3087", "CVE-2017-3098");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-08 01:29:00 +0000 (Sat, 08 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-06-21 18:20:28 +0530 (Wed, 21 Jun 2017)");
  ##Qod is reduced to 30, due to hotfix provided cannot be detected.
  script_tag(name:"qod", value:"30");
  script_name("Adobe Captivate < 10.0.0.192 Multiple Vulnerabilities (APSB17-19) - Windows");

  script_tag(name:"summary", value:"Adobe Captivate is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due an input validation error and security
  bypass error in the quiz reporting feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code on the target system, escalate privileges and disclose sensitive information.");

  script_tag(name:"affected", value:"Adobe Captivate prior to version 10.0.0.192.");

  script_tag(name:"solution", value:"Update to version 10.0.0.192 or later or apply the hotfix for
  Adobe Captivate 8 and 9.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/captivate/apsb17-19.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_captivate_detect.nasl");
  script_mandatory_keys("Adobe/Captivate/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"10.0.0.192")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.0.0.192");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
