# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:photoshop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821393");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2023-25908");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-27 21:15:00 +0000 (Mon, 27 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-15 13:14:56 +0530 (Wed, 15 Mar 2023)");
  script_name("Adobe Photoshop RCE Vulnerability (APSB23-23) - Windows");

  script_tag(name:"summary", value:"Adobe Photoshop is prone to a high-risk vulnerability that can
  lead to remote code execution (RCE).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a use-after-free
  error when processing files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  conduct arbitrary code execution on target system.");

  script_tag(name:"affected", value:"Adobe Photoshop 2022 prior to 23.5.4 and
  Adobe Photoshop 2023 prior to 24.2.1");

  script_tag(name:"solution", value:"Update to Adobe Photoshop 2022 23.5.4
  or Adobe Photoshop 2023 24.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb23-23.html");

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Installed");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^23\.")
{
  if(version_is_less(version:vers, test_version:"23.5.4")) {
    fix = "23.5.4";
    installed_ver = "Adobe Photoshop 2022";
  }
}

else if(vers =~ "^24\.")
{
  if(version_is_less(version:vers, test_version:"24.2.1"))
  {
    fix = "24.2.1";
    installed_ver = "Adobe Photoshop 2023";
  }
}
if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
