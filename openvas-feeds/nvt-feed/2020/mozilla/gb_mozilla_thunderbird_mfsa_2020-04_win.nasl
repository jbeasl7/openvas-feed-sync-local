# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815892");
  script_version("2024-02-15T05:05:40+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-17026", "CVE-2019-17015", "CVE-2019-17016", "CVE-2019-17017",
                "CVE-2019-17021", "CVE-2019-17022", "CVE-2019-17024");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-13 18:15:00 +0000 (Thu, 13 May 2021)");
  script_tag(name:"creation_date", value:"2020-01-14 14:59:36 +0530 (Tue, 14 Jan 2020)");
  script_name("Mozilla Thunderbird Security Advisory (MFSA2020-04) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An incorrect alias information in IonMonkey JIT compiler for setting array
    elements.

  - Memory corruption error in parent process during new content process
    initialization.

  - Bypass of @namespace CSS sanitization during pasting.

  - Type Confusion error in XPCVariant.cpp due to a missing case handling
    object types.

  - Heap address disclosure in parent process during content process initialization.

  - CSS sanitization does not escape HTML tags.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  disclose sensitive information, run arbitrary code and crash the affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 68.4.1.");

  script_tag(name:"solution", value:"Update to Mozilla Thunderbird version 68.4.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-04/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"68.4.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"68.4.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
