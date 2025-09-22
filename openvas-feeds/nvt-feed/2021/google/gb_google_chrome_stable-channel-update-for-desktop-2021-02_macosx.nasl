# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817900");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2021-21142", "CVE-2021-21143", "CVE-2021-21144", "CVE-2021-21145",
                "CVE-2021-21146", "CVE-2021-21147");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-01 02:15:00 +0000 (Sat, 01 May 2021)");
  script_tag(name:"creation_date", value:"2021-02-03 12:29:41 +0530 (Wed, 03 Feb 2021)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2021-02) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Multiple use after free errors.

  - An inappropriate implementation in Skia.

  - Multiple heap buffer overflow errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, gain access to sensitive data and launch denial of
  service attacks.");

  script_tag(name:"affected", value:"Google Chrome version prior to 88.0.4324.146
  on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  88.0.4324.146 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/02/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
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

if(version_is_less(version:chr_ver, test_version:"88.0.4324.146"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"88.0.4324.146", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
