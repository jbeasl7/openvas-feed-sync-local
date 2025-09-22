# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810202");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2016-4613", "CVE-2016-7578");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-25 17:13:00 +0000 (Mon, 25 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-11-17 12:45:37 +0530 (Thu, 17 Nov 2016)");
  script_name("Apple iTunes Code Execution And Information Disclosure Vulnerabilities (HT207274) - Windows");

  script_tag(name:"summary", value:"Apple iTunes is prone to information disclosure and code
  execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An input validation error in state management.

  - Multiple memory corruption errors in memory handling");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code and disclose user information.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.5.2 on Windows.");

  script_tag(name:"solution", value:"Update to version 12.5.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207274");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93949");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_is_less(version:version, test_version:"12.5.2.36")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.5.2.36", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
