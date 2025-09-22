# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820017");
  script_version("2025-09-19T15:40:40+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-26485", "CVE-2022-26486");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-30 20:55:00 +0000 (Fri, 30 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-03-07 11:58:53 +0530 (Mon, 07 Mar 2022)");
  script_name("Mozilla Firefox Security Advisory (MFSA2022-09) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  use-after-free vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use-after-free in WebGPU IPC Framework.

  - Use-after-free in XSLT parameter processing.");

  script_tag(name:"impact", value:"Successful exploitation can lead to arbitrary
  code execution or allow an attacker to gain remote code execution capabilities and
  cause denial of service condition.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 97.0.2
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 97.0.2
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-09/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
ffVer = infos["version"];
ffPath = infos["location"];

if(version_is_less(version:ffVer, test_version:"97.0.2"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"97.0.2", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
