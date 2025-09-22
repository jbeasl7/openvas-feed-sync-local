# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813558");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2018-4145", "CVE-2018-4261", "CVE-2018-4262", "CVE-2018-4263",
                "CVE-2018-4264", "CVE-2018-4265", "CVE-2018-4266", "CVE-2018-4267",
                "CVE-2018-4270", "CVE-2018-4271", "CVE-2018-4272", "CVE-2018-4273",
                "CVE-2018-4278", "CVE-2018-4284", "CVE-2018-4293");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-04 19:35:00 +0000 (Thu, 04 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-07-10 13:34:53 +0530 (Tue, 10 Jul 2018)");
  script_name("Apple iTunes Security Updates (HT208933) - Windows");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A cookie management issue in improved checks.

  - A memory corruption issue in memory handling.

  - Sound fetched through audio elements exfiltrated cross-origin.

  - A type confusion issue in memory handling.

  - A race condition in validation.

  - Multiple memory corruption issues in memory handling.

  - Multiple memory corruption issues in input validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to crash Safari,
  exfiltrate audio data cross-origin, execute arbitrary code and cause a denial of service.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.8 on Windows.");

  script_tag(name:"solution", value:"Update to version 12.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208933");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

if(version_is_less(version:version, test_version:"12.8.0.150")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.8.0.150", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
