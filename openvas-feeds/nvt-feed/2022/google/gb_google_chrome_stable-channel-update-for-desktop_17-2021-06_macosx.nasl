# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826805");
  script_version("2025-09-12T05:38:45+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-30554", "CVE-2021-30555", "CVE-2021-30556", "CVE-2021-30557");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-18 03:15:00 +0000 (Sun, 18 Jul 2021)");
  script_tag(name:"creation_date", value:"2022-12-07 17:04:11 +0530 (Wed, 07 Dec 2022)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_17-2021-06) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple after free
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to, multiple use
  after free vulnerabilities in WebGL, Sharing, WebAudio, TabGroups.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code and corrupt memory on affected system.");

  script_tag(name:"affected", value:"Google Chrome versions prior to
  91.0.4472.114 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  91.0.4472.114 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/06/stable-channel-update-for-desktop_17.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"91.0.4472.114")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"91.0.4472.114", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
