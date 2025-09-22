# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815495");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2019-8625", "CVE-2019-8707", "CVE-2019-8719", "CVE-2019-8720",
                "CVE-2019-8726", "CVE-2019-8728", "CVE-2019-8733", "CVE-2019-8734",
                "CVE-2019-8735", "CVE-2019-8741", "CVE-2019-8743", "CVE-2019-8745",
                "CVE-2019-8746", "CVE-2019-8749", "CVE-2019-8750", "CVE-2019-8751",
                "CVE-2019-8752", "CVE-2019-8756", "CVE-2019-8762", "CVE-2019-8763",
                "CVE-2019-8764", "CVE-2019-8765", "CVE-2019-8766", "CVE-2019-8773",
                "CVE-2019-8825");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-29 17:51:17 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-10-10 11:25:57 +0530 (Thu, 10 Oct 2019)");
  script_name("Apple iTunes Security Updates (HT210635)");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer overflow error due to improper bounds checking.

  - A logic issue due to improper state management.

  - Multiple memory corruption issues due to improper memory handling.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to conduct
  cross site scripting attacks and execute arbitrary code by processing maliciously crafted web
  content.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.10.1.");

  script_tag(name:"solution", value:"Update to version 12.10.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210635");
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

if(version_is_less(version:version, test_version:"12.10.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.10.1", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
