# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:creative_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813878");
  script_version("2024-02-27T14:36:53+0000");
  script_cve_id("CVE-2018-12829");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-27 14:36:53 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-05 17:31:00 +0000 (Mon, 05 Nov 2018)");
  script_tag(name:"creation_date", value:"2018-08-29 10:49:58 +0530 (Wed, 29 Aug 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Creative Cloud Security Update (APSB18-32) - Windows");

  script_tag(name:"summary", value:"Adobe Creative cloud is prone to a privilege escalation vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper certificate
  validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to escalate privileges and bypass security restrictions.");

  script_tag(name:"affected", value:"Adobe Creative Cloud before 4.6.1
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Creative Cloud version
  4.6.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/creative-cloud/apsb18-32.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_win.nasl");
  script_mandatory_keys("AdobeCreativeCloud/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
cloudVer = infos["version"];
cloudPath = infos["location"];

if(version_is_less(version:cloudVer, test_version:"4.6.1"))
{
  report = report_fixed_ver(installed_version:cloudVer, fixed_version:"4.6.1", install_path:cloudPath);
  security_message(data:report);
  exit(0);
}
exit(0);
