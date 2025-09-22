# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826948");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2021-30565", "CVE-2021-30566", "CVE-2021-30567", "CVE-2021-30568",
                "CVE-2021-30569", "CVE-2021-30571", "CVE-2021-30572", "CVE-2021-30573",
                "CVE-2021-30574", "CVE-2021-30575", "CVE-2021-30576", "CVE-2021-30577",
                "CVE-2021-30578", "CVE-2021-30579", "CVE-2021-30580", "CVE-2021-30581",
                "CVE-2021-30582", "CVE-2021-30583", "CVE-2021-30584", "CVE-2021-30585",
                "CVE-2021-30586", "CVE-2021-30587", "CVE-2021-30588", "CVE-2021-30589",
                "CVE-2021-38023");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-10 20:35:00 +0000 (Tue, 10 Aug 2021)");
  script_tag(name:"creation_date", value:"2023-03-23 15:53:09 +0530 (Thu, 23 Mar 2023)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_20-2021-07) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Out of bounds write in Tab Groups.

  - Stack buffer overflow in Printing.

  - Multiple use after free errors.

  - Heap buffer overflow in WebGL.

  - Insufficient policy enforcement in DevTools.

  - Out of bounds read in Autofill.

  - Insufficient policy enforcement in Installer.

  - Uninitialized Use in Media.

  - Insufficient policy enforcement in Android intents.

  - Inappropriate implementation in Animation.

  - Insufficient policy enforcement in image handling on Windows.

  - Incorrect security UI in Downloads.

  - Inappropriate implementation in Compositing on Windows.

  - Type Confusion in V8.

  - Insufficient validation of untrusted input in Sharing.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  92.0.4515.107 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  92.0.4515.107 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/07/stable-channel-update-for-desktop_20.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"92.0.4515.107")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"92.0.4515.107", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
