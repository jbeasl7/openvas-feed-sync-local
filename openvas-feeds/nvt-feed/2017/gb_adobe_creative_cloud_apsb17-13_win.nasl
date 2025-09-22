# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:creative_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811018");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2017-3006", "CVE-2017-3007");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-04 12:14:45 +0530 (Thu, 04 May 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Creative Cloud Security Update (APSB17-13) - Windows");

  script_tag(name:"summary", value:"Adobe Creative Cloud is prone to a security bypass and a remote
  code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The use of improper resource permissions during the installation of Creative
    Cloud desktop applications.

  - An error related to the directory search path used to find resources.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to gain elevated privileges and leads to code execution.
  Failed exploit attempts will likely cause a denial-of-service condition.");

  script_tag(name:"affected", value:"Adobe Creative Cloud before version 4.0.0.185.");

  script_tag(name:"solution", value:"Update to Adobe Creative Cloud version
  4.0.0.185 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/creative-cloud/apsb17-13.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97555");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97558");
  script_xref(name:"URL", value:"http://hyp3rlinx.altervista.org/advisories/ADOBE-CREATIVE-CLOUD-PRIVILEGE-ESCALATION.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_win.nasl");
  script_mandatory_keys("AdobeCreativeCloud/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"4.0.0.185")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.0.0.185");
  security_message(data:report);
  exit(0);
}

exit(99);
