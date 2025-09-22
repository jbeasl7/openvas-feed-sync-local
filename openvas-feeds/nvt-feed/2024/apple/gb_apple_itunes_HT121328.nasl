# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834634");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-44157", "CVE-2024-44193");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-11 02:53:58 +0000 (Wed, 11 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-10-03 07:37:39 +0530 (Thu, 03 Oct 2024)");
  script_name("Apple iTunes Security Update (HT121328)");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-44193: Logic issue

  - CVE-2024-44157: A stack buffer overflow while parsing a maliciously crafted video file");

  script_tag(name:"impact", value:"Successful exploitation may lead to unexpected system
  termination or may allow an attacker to elevate their privileges.");

  script_tag(name:"affected", value:"Apple iTunes prior to version 12.13.3.");

  script_tag(name:"solution", value:"Update to version 12.13.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/121328");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_itunes_smb_login_detect.nasl");
  script_mandatory_keys("apple/itunes/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"12.13.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.13.3", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
