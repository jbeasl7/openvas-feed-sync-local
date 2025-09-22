# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805934");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2015-1271", "CVE-2015-1273", "CVE-2015-1274", "CVE-2015-1276",
                "CVE-2015-1279", "CVE-2015-1280", "CVE-2015-1281", "CVE-2015-1282",
                "CVE-2015-1283", "CVE-2015-1284", "CVE-2015-1286", "CVE-2015-1287",
                "CVE-2015-1270", "CVE-2015-1272", "CVE-2015-1277", "CVE-2015-1278",
                "CVE-2015-1285", "CVE-2015-1288", "CVE-2015-1289", "CVE-2015-5605",
                "CVE-2015-1290");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2015-07-23 13:02:12 +0530 (Thu, 23 Jul 2015)");
  script_name("Google Chrome Multiple Vulnerabilities-01 (Jul 2015) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple heap based buffer-overflow in pdfium.

  - An error which allows executable files to run immediately after download.

  - A use-after-free error in IndexedDB.

  - A memory corruption error in skia.

  - An error allowing content security policy (CSP) bypass.

  - A use-after-free error in pdfium.

  - A heap based buffer-overflow in expat.

  - A use-after-free error in blink.

  - Universal cross-site scripting (UXSS) error in blink.

  - An error in cascading style sheets (CSS) allowing to bypass same origin
  policy.

  - Uninitialized memory read error in ICU.

  - A use-after-free error related to unexpected GPU process termination.

  - A use-after-free error in accessibility.

  - An error leading to URL spoofing using pdf files.

  - An error leading to information leak in XSS auditor.

  - An error allowing spell checking dictionaries to be fetched over HTTP.

  - The regular-expression implementation in Google V8 mishandles interrupts.

  - Various other unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass security restrictions, cause a denial of service condition
  or potentially execute arbitrary code, conduct spoofing attack, gain sensitive
  information and other unspecified impacts.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  44.0.2403.89 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  44.0.2403.89 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2015/07/stable-channel-update_21.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75973");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76007");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"44.0.2403.89")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"44.0.2403.89", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
