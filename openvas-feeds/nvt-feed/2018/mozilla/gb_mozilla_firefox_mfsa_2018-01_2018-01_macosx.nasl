# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812296");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-05 11:31:00 +0000 (Tue, 05 May 2020)");
  script_tag(name:"creation_date", value:"2018-01-05 14:36:34 +0530 (Fri, 05 Jan 2018)");
  script_name("Mozilla Firefox Security Advisories (MFSA2018-01, MFSA2018-01) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:
  multiple errors leading to 'speculative execution side-channel attacks'
  that affect many modern processors, operating systems and browser
  JavaScript engines.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow code on a malicious web page to read data from
  other web sites (violating the same-origin policy) or private data from the
  browser itself.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 57.0.4 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 57.0.4
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-01");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ffVer = infos["version"];
ffPath = infos["location"];

if(version_is_less(version:ffVer, test_version:"57.0.4"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"57.0.4", install_path:ffPath);
  security_message(data:report);
  exit(0);
}

exit(99);
