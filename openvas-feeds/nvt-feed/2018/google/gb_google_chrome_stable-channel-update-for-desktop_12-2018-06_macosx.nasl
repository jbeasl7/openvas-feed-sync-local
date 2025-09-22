# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813605");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-6149");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-02 13:30:00 +0000 (Tue, 02 Jul 2019)");
  script_tag(name:"creation_date", value:"2018-06-14 10:21:07 +0530 (Thu, 14 Jun 2018)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop_12-2018-06) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an out of bounds write
  error in V8.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to cause an out-of-bounds write to arbitrary locations in memory.");

  script_tag(name:"affected", value:"Google Chrome version prior to 67.0.3396.87
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 67.0.3396.87
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/06/stable-channel-update-for-desktop_12.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos["version"];
chr_path = infos["location"];

if(version_is_less(version:chr_ver, test_version:"67.0.3396.87"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"67.0.3396.87", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(0);
