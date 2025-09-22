# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821254");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2022-1853", "CVE-2022-1854", "CVE-2022-1855", "CVE-2022-1856",
                "CVE-2022-1857", "CVE-2022-1858", "CVE-2022-1859", "CVE-2022-1860",
                "CVE-2022-1861", "CVE-2022-1862", "CVE-2022-1863", "CVE-2022-1864",
                "CVE-2022-1865", "CVE-2022-1866", "CVE-2022-1867", "CVE-2022-1868",
                "CVE-2022-1869", "CVE-2022-1870", "CVE-2022-1871", "CVE-2022-1872",
                "CVE-2022-1873", "CVE-2022-1874", "CVE-2022-1875", "CVE-2022-1876",
                "CVE-2022-4918");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-03 12:36:00 +0000 (Wed, 03 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-06-01 15:36:20 +0530 (Wed, 01 Jun 2022)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop_24-2022-05) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple use after free errors in Indexed DB, ANGLE, Messaging, User Education, etc.

  - Insufficient policy enforcement in File System API.

  - Out of bounds read in DevTools.

  - Inappropriate implementation in Extensions.

  - Insufficient validation of untrusted input in Data Transfer.

  - Type Confusion in V8.

  - Multiple insufficient policy enforcement errors in Extensions API, COOP, and Safe Browsing.

  - Inappropriate implementation in PDF.

  - Heap buffer overflow in DevTools.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct out-of-bounds memory access, execute arbitrary code, disclose sensitive
  information and cause a denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 102.0.5005.61
  on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 102.0.5005.61
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/05/stable-channel-update-for-desktop_24.html");
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

if(version_is_less(version:vers, test_version:"102.0.5005.61")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.0.5005.61", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
