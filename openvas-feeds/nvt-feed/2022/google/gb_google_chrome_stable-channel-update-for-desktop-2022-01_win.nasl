# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819946");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2022-0096", "CVE-2022-0097", "CVE-2022-0098", "CVE-2022-0099",
                "CVE-2022-0100", "CVE-2022-0101", "CVE-2022-0102", "CVE-2022-0103",
                "CVE-2022-0104", "CVE-2022-0105", "CVE-2022-0106", "CVE-2022-0107",
                "CVE-2022-0108", "CVE-2022-0109", "CVE-2022-0110", "CVE-2022-0111",
                "CVE-2022-0112", "CVE-2022-0113", "CVE-2022-0114", "CVE-2022-0115",
                "CVE-2022-0116", "CVE-2022-0117", "CVE-2022-0118", "CVE-2022-0120",
                "CVE-2022-4925", "CVE-2022-4924");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-22 17:51:00 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-01-14 10:56:38 +0530 (Fri, 14 Jan 2022)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2022-01) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple use after free errors.

  - Type confusion error in V8.

  - Multiple heap buffer overflow errors.

  - Multiple implementation errors.

  - Policy bypass error.

  - Uninitialized Use in File API.

  - Out of bounds memory access in Web Serial.

  - Multiple security bypass errors.

  - Insufficient validation of untrusted input in QUIC.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  obtain sensitive information, bypass security restrictions, execute arbitrary code
  and cause denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 97.0.4692.71
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 97.0.4692.71
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/01/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos["version"];
chr_path = infos["location"];

if(version_is_less(version:chr_ver, test_version:"97.0.4692.71"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"97.0.4692.71", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
