# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832077");
  script_version("2025-06-04T05:40:50+0000");
  script_cve_id("CVE-2023-32205", "CVE-2023-32206", "CVE-2023-32207", "CVE-2023-32208",
                "CVE-2023-32209", "CVE-2023-32210", "CVE-2023-32211", "CVE-2023-32212",
                "CVE-2023-32213", "CVE-2023-32215", "CVE-2023-32216", "CVE-2023-32570");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-06-04 05:40:50 +0000 (Wed, 04 Jun 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-27 08:25:00 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-05-11 15:34:01 +0530 (Thu, 11 May 2023)");
  script_name("Mozilla Firefox Security Advisories (MFSA2023-16) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Browser prompts could have been obscured by popups.

  - Crash in RLBox Expat driver.

  - Potential permissions request bypass via clickjacking.

  - Leak of script base URL in service workers via import().

  - Persistent DoS via favicon image.

  - Incorrect principal object ordering.

  - Content process crash due to invalid wasm code.

  - Potential spoof due to obscured address bar.

  - Potential memory corruption in FileReader::DoReadData().");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  disclose sensitive information, execute arbitrary code and cause denial of service
  condition.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 113 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 113 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-16/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"113")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"113", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
