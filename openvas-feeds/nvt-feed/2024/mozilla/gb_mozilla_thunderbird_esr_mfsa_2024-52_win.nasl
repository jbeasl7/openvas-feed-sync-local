# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834704");
  script_version("2025-09-09T14:09:45+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-9680");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-16 15:07:36 +0000 (Wed, 16 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-23 11:12:04 +0530 (Wed, 23 Oct 2024)");
  script_name("Mozilla Thunderbird ESR Security Update (MFSA2024-52) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird ESR is prone to an use
  after free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name: "insight" , value:"The flaw exists due to an use after free
  error in Animation timelines.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to achieve code execution.");

  script_tag(name: "affected" , value:"Mozilla Thunderbird ESR prior to version
  115.16.0 and 128.0 before 128.3.1 on Windows.");

  script_tag(name: "solution" , value:"Update to version 115.16.0, 128.3.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-52/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.16.0")) {
  fix = "115.16.0";
}

if(version_in_range_exclusive(version: vers, test_version_lo: "128.0", test_version_up: "128.3.1")) {
  fix = "128.3.1";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
