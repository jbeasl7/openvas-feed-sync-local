# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814885");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-5805", "CVE-2019-5806", "CVE-2019-5807", "CVE-2019-5808",
                "CVE-2019-5809", "CVE-2019-5810", "CVE-2019-5811", "CVE-2019-5812",
                "CVE-2019-5813", "CVE-2019-5814", "CVE-2019-5815", "CVE-2019-5816",
                "CVE-2019-5817", "CVE-2019-5818", "CVE-2019-5819", "CVE-2019-5820",
                "CVE-2019-5821", "CVE-2019-5822", "CVE-2019-5823");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-11 14:43:00 +0000 (Tue, 11 Oct 2022)");
  script_tag(name:"creation_date", value:"2019-04-26 13:07:09 +0530 (Fri, 26 Apr 2019)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop_23-2019-04) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use after free errors in PDFium and Blink

  - An integer overflow error in Angle.

  - A memory corruption issue in V8.

  - A user information disclosure in Autofill.

  - Multiple CORS bypass errors in Blink and download manager.

  - A URL spoof error in Omnibox on iOS.

  - An out of bounds read error in V8.

  - Heap buffer overflow errors in Blink and Angle on Windows.

  - An uninitialized value error in media reader.

  - A forced navigation error from service worker.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the browser, gain access to sensitive
  information, bypass security restrictions and perform unauthorized actions, or
  cause denial-of-service conditions.");

  script_tag(name:"affected", value:"Google Chrome version prior to 74.0.3729.108 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 74.0.3729.108
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/04/stable-channel-update-for-desktop_23.html");
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

if(version_is_less(version:vers, test_version:"74.0.3729.108"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"74.0.3729.108", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
