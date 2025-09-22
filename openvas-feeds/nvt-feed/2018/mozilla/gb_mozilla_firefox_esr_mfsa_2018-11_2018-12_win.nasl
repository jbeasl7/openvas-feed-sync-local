# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813359");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2018-5183", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5157",
                "CVE-2018-5158", "CVE-2018-5159", "CVE-2018-5168", "CVE-2018-5174",
                "CVE-2018-5178", "CVE-2018-5150");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-13 13:24:00 +0000 (Wed, 13 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-05-11 12:34:59 +0530 (Fri, 11 May 2018)");
  script_name("Mozilla Firefox ESR Security Advisories (MFSA2018-11, MFSA2018-12) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Backport critical security fixes in Skia.

  - Use-after-free error with SVG animations and clip paths.

  - Use-after-free error with SVG animations and text paths.

  - Same-origin bypass of PDF Viewer to view protected PDF files.

  - Malicious PDF can inject JavaScript into PDF Viewer.

  - Integer overflow and out-of-bounds write errors in Skia.

  - Lightweight themes can be installed without user interaction.

  - Windows Defender SmartScreen UI runs with less secure behavior for downloaded files.

  - Buffer overflow error during UTF-8 to Unicode string conversion through legacy extension.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, bypass security restrictions corrupt memory
  and cause denial of service condition.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 52.8 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 52.8
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-12");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"52.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"52.8", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
