# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815828");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2019-8782", "CVE-2019-8783", "CVE-2019-8784", "CVE-2019-8801",
                "CVE-2019-8808", "CVE-2019-8811", "CVE-2019-8812", "CVE-2019-8813",
                "CVE-2019-8814", "CVE-2019-8815", "CVE-2019-8816", "CVE-2019-8819",
                "CVE-2019-8820", "CVE-2019-8821", "CVE-2019-8822", "CVE-2019-8823",
                "CVE-2019-8827");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-18 13:16:00 +0000 (Tue, 18 May 2021)");
  script_tag(name:"creation_date", value:"2019-11-05 15:24:05 +0530 (Tue, 05 Nov 2019)");
  script_name("Apple iTunes Security Updates (HT210726)");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A dynamic library loading issue existed in iTunes setup.

  - A logic issue related to improper state management.

  - Multiple memory corruption issues.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to conduct
  cross site scripting attacks and execute arbitrary code.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.10.2 on Windows.");

  script_tag(name:"solution", value:"Update to version 12.10.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210726");

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

if(version_is_less(version:version, test_version:"12.10.2")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.10.2", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
