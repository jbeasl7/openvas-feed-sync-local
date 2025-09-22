# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814016");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-17458", "CVE-2018-17459");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-09-17 11:13:14 +0530 (Mon, 17 Sep 2018)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2018-09_11) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - URL spoof in Omnibox.

  - Function signature mismatch in WebAssembly.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers
  to conduct spoofing attacks and bypass security restrictions.");

  script_tag(name:"affected", value:"Google Chrome version prior to 69.0.3497.92
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  69.0.3497.92 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/09/stable-channel-update-for-desktop_11.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos["version"];
chr_path = infos["location"];

if(version_is_less(version:chr_ver, test_version:"69.0.3497.92"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"69.0.3497.92", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(0);
