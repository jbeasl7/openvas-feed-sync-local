# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812819");
  script_version("2025-09-12T05:38:45+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-6057", "CVE-2018-6058", "CVE-2018-6059", "CVE-2018-6060",
                "CVE-2018-6061", "CVE-2018-6062", "CVE-2018-6063", "CVE-2018-6064",
                "CVE-2018-6065", "CVE-2018-6066", "CVE-2018-6067", "CVE-2018-6068",
                "CVE-2018-6069", "CVE-2018-6070", "CVE-2018-6071", "CVE-2018-6072",
                "CVE-2018-6073", "CVE-2018-6074", "CVE-2018-6075", "CVE-2018-6076",
                "CVE-2018-6077", "CVE-2018-6078", "CVE-2018-6079", "CVE-2018-6080",
                "CVE-2018-6081", "CVE-2018-6082", "CVE-2018-6083");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-03-07 11:13:56 +0530 (Wed, 07 Mar 2018)");
  script_name("Google Chrome Multiple Security Vulnerabilities (Mar 2018) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple use after free errors in flash and Blink.

  - Race condition, type confusion and integer overflow errors in V8.

  - Buffer overflows errors in Skia, PDFium and WebGL.

  - Multiple incorrect permission errors on shared memory.

  - Same origin bypass error via canvas.

  - CSP bypass error through extensions.

  - Object lifecycle issues in Chrome custom.

  - Mark-of-the-Web bypass error.

  - Overly permissive cross origin download errors.

  - Timing attack error using SVG filters.

  - URL Spoof error in OmniBox.

  - Information disclosure error in IPC call.

  - XSS due to input validation error in interstitials.

  - Circumvention of port blocking error.

  - Incorrect processing error of AppManifests.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial of service, manipulate shared memory, bypass the same origin
  policy, content-security-policy and mark-of-the-web, allow overly permissive
  cross origin downloads, spoof the URL, disclose sensitive information, perform
  cross site scripting or possibly have other unspecified impacts via crafted
  dimensions.");

  script_tag(name:"affected", value:"Google Chrome versions prior to 65.0.3325.146 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  65.0.3325.146 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/03/stable-channel-update-for-desktop.html");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"65.0.3325.146")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"65.0.3325.146", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
