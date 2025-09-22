# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815871");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-13725", "CVE-2019-13726", "CVE-2019-13727", "CVE-2019-13728",
                "CVE-2019-13729", "CVE-2019-13730", "CVE-2019-13732", "CVE-2019-13734",
                "CVE-2019-13735", "CVE-2019-13764", "CVE-2019-13736", "CVE-2019-13737",
                "CVE-2019-13738", "CVE-2019-13739", "CVE-2019-13740", "CVE-2019-13741",
                "CVE-2019-13742", "CVE-2019-13743", "CVE-2019-13744", "CVE-2019-13745",
                "CVE-2019-13746", "CVE-2019-13747", "CVE-2019-13748", "CVE-2019-13749",
                "CVE-2019-13750", "CVE-2019-13751", "CVE-2019-13752", "CVE-2019-13753",
                "CVE-2019-13754", "CVE-2019-13755", "CVE-2019-13756", "CVE-2019-13757",
                "CVE-2019-13758", "CVE-2019-13759", "CVE-2019-13761", "CVE-2019-13762",
                "CVE-2019-13763");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-16 12:15:00 +0000 (Mon, 16 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-12 12:30:31 +0530 (Thu, 12 Dec 2019)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2019-12) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple use after free errors in Bluetooth, WebSockets, WebAudio.

  - A heap buffer overflow error in password manager.

  - An insufficient policy enforcement in WebSockets.

  - Multiple out of bounds write errors in V8, SQLite.

  - A type confusion error in V8.

  - An integer overflow error in PDFium.

  - An insufficient policy enforcement in autocomplete, navigation, cookies, audio, omnibox, developer tools, extensions, downloads and payments.

  - An incorrect security UI in Omnibox, sharing, external protocol handling, printing, interstitials.

  - An insufficient validation of untrusted input in Blink.

  - An uninitialized use in rendering.

  - An insufficient data validation in SQLite.

  - An uninitialized use in SQLite.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose sensitive information, execute arbitrary code, bypass security
  restrictions and cause denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 79.0.3945.79 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 79.0.3945.79
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/12/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"79.0.3945.79"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"79.0.3945.79", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
