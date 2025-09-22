# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836340");
  script_version("2025-05-22T05:40:21+0000");
  script_cve_id("CVE-2025-4918", "CVE-2025-4919");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-05-22 05:40:21 +0000 (Thu, 22 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-20 11:55:55 +0530 (Tue, 20 May 2025)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2025-38) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform an out-of-bounds read or write on a JavaScript object.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR prior to version
  115.23.1 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 115.23.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-38/");
  script_xref(name:"URL", value:"https://blog.mozilla.org/security/2025/05/17/firefox-security-response-to-pwn2own-2025/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/blog/2025/5/16/pwn2own-berlin-2025-day-two-results");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/blog/2025/5/17/pwn2own-berlin-2025-day-three-results");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"115.23.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.23.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
