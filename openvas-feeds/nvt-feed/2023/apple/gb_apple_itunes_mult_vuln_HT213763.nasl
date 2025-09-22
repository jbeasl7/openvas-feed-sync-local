# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826992");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2023-32351", "CVE-2023-32353", "CVE-2023-32430");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-29 20:42:00 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-05-25 11:01:11 +0530 (Thu, 25 May 2023)");
  script_name("Apple iTunes Security Updates (HT213763)");

  script_tag(name:"summary", value:"The host is missing an important security update according to
  Apple.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple logic issues associated
  with improper checks.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to elevate
  privileges.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.12.9.");

  script_tag(name:"solution", value:"Update to version 12.12.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213763");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_itunes_smb_login_detect.nasl");
  script_mandatory_keys("apple/itunes/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("smb_nt.inc");
include("secpod_reg.inc");

if(hotfix_check_sp(win2016:1, win10:1, win10x64:1, win2019:1) <= 0)
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"12.12.9")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.12.9", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
