# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:creative_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834056");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2024-34116");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-19 17:40:23 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-06-13 12:03:54 +0530 (Thu, 13 Jun 2024)");
  script_name("Creative Cloud Desktop Application Arbitrary Code Execution Vulnerability APSB24-44 (Windows)");

  script_tag(name:"summary", value:"Adobe Creative Cloud Desktop Application is
  prone to an arbitrary code execution Vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to untrusted search
  path elements in creative cloud desktop application.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Creative Cloud Desktop Application
  6.1.0.587 and prior on Windows.");

  script_tag(name:"solution", value:"Update to version 6.2.0.554 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/creative-cloud/apsb24-44.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_win.nasl");
  script_mandatory_keys("AdobeCreativeCloud/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"6.2.0.554")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.2.0.554", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(0);
