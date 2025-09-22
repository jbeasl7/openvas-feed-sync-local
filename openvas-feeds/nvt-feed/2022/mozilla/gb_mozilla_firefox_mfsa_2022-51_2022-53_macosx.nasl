# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826817");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2022-46871", "CVE-2022-46873", "CVE-2022-46874", "CVE-2022-46875",
                "CVE-2022-46877", "CVE-2022-46878", "CVE-2022-46879");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 15:57:00 +0000 (Wed, 04 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-12-16 11:26:31 +0530 (Fri, 16 Dec 2022)");
  script_name("Mozilla Firefox Security Advisories (MFSA2022-51, MFSA2022-53) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - libusrsctp library out of date.

  - Firefox did not implement the CSP directive unsafe-hashes.

  - Drag and Dropped Filenames could have been truncated to malicious extensions.

  - Download Protections were bypassed by .atloc and .ftploc files on Mac OS X.

  - Fullscreen notification bypass.

  - Memory safety bugs fixed in Firefox 108 and Firefox ESR 102.6.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  108 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 108
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-51/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"108")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"108", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
