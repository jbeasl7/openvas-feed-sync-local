# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832883");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-0743", "CVE-2024-2608", "CVE-2024-2616", "CVE-2023-5388",
                "CVE-2024-2610", "CVE-2024-2611", "CVE-2024-2612", "CVE-2024-2614");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-25 14:47:29 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-03-25 11:21:25 +0530 (Mon, 25 Mar 2024)");
  script_name("Mozilla Firefox ESR Security Update (MFSA2024-13) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-0743: Crash in NSS TLS method

  - CVE-2024-2610: Improper handling of html and body tags enabled CSP nonce leakage

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to obtain sensitive information and conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR prior to version
  115.9 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 115.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-13/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"115.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.9", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

