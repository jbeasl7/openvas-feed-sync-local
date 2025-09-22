# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816583");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2020-6383", "CVE-2020-6384", "CVE-2020-6386");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-11 17:15:00 +0000 (Wed, 11 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-02-25 17:17:39 +0530 (Tue, 25 Feb 2020)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_18-2020-02) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - A type confusion error in V8.

  - An use after free in WebAudio.

  - An use after free in speech.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code or crash affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 80.0.3987.116.");

  script_tag(name:"solution", value:"Update to Google Chrome version
  80.0.3987.116 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/02/stable-channel-update-for-desktop_18.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"80.0.3987.116")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"80.0.3987.116", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
