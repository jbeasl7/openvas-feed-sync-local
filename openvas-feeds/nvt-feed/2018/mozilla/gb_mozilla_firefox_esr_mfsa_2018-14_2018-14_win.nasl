# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813394");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2018-6126");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-15 21:50:00 +0000 (Tue, 15 Jan 2019)");
  script_tag(name:"creation_date", value:"2018-06-07 10:54:10 +0530 (Thu, 07 Jun 2018)");
  script_name("Mozilla Firefox ESR Security Advisories (MFSA2018-14, MFSA2018-14) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw exists due to a heap buffer
  overflow can occur in the Skia library when rasterizing paths using a
  maliciously crafted SVG file with anti-aliasing turned off.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to result in a potentially
  exploitable crash.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  52.8.1  and 60.x before 60.0.2 on Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox ESR version
  52.8.1 or 60.0.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-14");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"52.8.1")){
  fix = "52.8.1";
}

else if(vers =~ "^(60\.0)" && version_is_less(version:vers, test_version:"60.0.2")){
  fix = "60.0.2";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
