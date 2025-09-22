# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826792");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2022-46871", "CVE-2023-23601", "CVE-2023-23602", "CVE-2022-46877",
                "CVE-2023-23603", "CVE-2023-23605");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-08 13:46:00 +0000 (Thu, 08 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-01-18 13:24:34 +0530 (Wed, 18 Jan 2023)");
  script_name("Mozilla Firefox ESR Security Advisories (MFSA2022-54, MFSA2023-02) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - libusrsctp library out of date.

  - Malicious command could be hidden in devtools output on Windows.

  - URL being dragged from cross-origin iframe into same tab triggers navigation.

  - Content Security Policy wasn't being correctly applied to WebSockets
    in WebWorkers.

  - Fullscreen notification bypass.

  - Calls to <code>console.log</code> allowed bypassing Content Security Policy
     via format directive.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code, disclose sensitive information and
  conduct spoofing attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  102.7 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 102.7
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-02/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"102.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.7", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
