# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811848");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-7793", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7824",
                "CVE-2017-7805", "CVE-2017-7812", "CVE-2017-7814", "CVE-2017-7813",
                "CVE-2017-7815", "CVE-2017-7816", "CVE-2017-7821", "CVE-2017-7823",
                "CVE-2017-7822", "CVE-2017-7820", "CVE-2017-7811", "CVE-2017-7810");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-30 16:56:00 +0000 (Mon, 30 Jul 2018)");
  script_tag(name:"creation_date", value:"2017-10-03 15:33:22 +0530 (Tue, 03 Oct 2017)");
  script_name("Mozilla Firefox Security Advisories (MFSA2017-21, MFSA2017-22) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use-after-free error with Fetch API.

  - Firefox for Android address bar spoofing through full screen mode.

  - Use-after-free error during ARIA array manipulation.

  - Use-after-free error while resizing images in design mode.

  - Buffer overflow error when drawing and validating elements with ANGLE.

  - Use-after-free error in TLS 1.2 generating handshake hashes.

  - Drag and drop of malicious page content to the tab bar can open locally stored files.

  - Blob and data URLs bypass phishing and malware protection warnings.

  - Integer truncation in the JavaScript parser.

  - OS X fonts render some Tibetan and Arabic unicode characters as spaces.

  - Spoofing attack with modal dialogs on non-e10s installations.

  - Web Extensions can load about: URLs in extension UI.

  - Web Extensions can download and open non-executable files without user interaction.

  - CSP sandbox directive did not create a unique origin.

  - Web Crypto allows AES-GCM with 0-length IV.

  - Xray wrapper bypass with new tab and web console.

  - Memory safety bugs fixed in Firefox 56.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to cause denial of service, conduct
  spoofing attack, obtain sensitive information and execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox versions before 56.0.");

  script_tag(name:"solution", value:"Update to version 56.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-21");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101055");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101053");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101059");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101057");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101054");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"56.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"56.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
