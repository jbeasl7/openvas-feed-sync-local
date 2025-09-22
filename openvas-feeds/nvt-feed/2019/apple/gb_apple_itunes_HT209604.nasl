# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814875");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2019-6201", "CVE-2019-7285", "CVE-2019-7292", "CVE-2019-8503",
                "CVE-2019-8506", "CVE-2019-8515", "CVE-2019-8518", "CVE-2019-8523",
                "CVE-2019-8524", "CVE-2019-8535", "CVE-2019-8536", "CVE-2019-8542",
                "CVE-2019-8544", "CVE-2019-8551", "CVE-2019-8556", "CVE-2019-8558",
                "CVE-2019-8559", "CVE-2019-8562", "CVE-2019-8563", "CVE-2019-8638",
                "CVE-2019-8639");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-18 13:00:00 +0000 (Tue, 18 May 2021)");
  script_tag(name:"creation_date", value:"2019-03-26 10:32:20 +0530 (Tue, 26 Mar 2019)");
  script_name("Apple iTunes Security Updates (HT209604)");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer overflow error,

  - A type confusion error,

  - Multiple memory corruption issues,

  - A cross-origin issue with the fetch API,

  - A use after free error,

  - A logic issue and

  - A validation issue.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability will allow remote
  attackers to elevate privileges, execute scripts, circumvent sandbox restrictions, execute
  arbitrary code, read sensitive user information and process memory, conduct universal cross site
  scripting by processing maliciously crafted web content.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.9.4.");

  script_tag(name:"solution", value:"Update to version 12.9.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209604");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
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

if(version_is_less(version:version, test_version:"12.9.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.9.4", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
