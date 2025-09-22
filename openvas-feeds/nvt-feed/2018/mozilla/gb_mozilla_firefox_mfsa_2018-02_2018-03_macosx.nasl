# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812669");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2018-5091", "CVE-2018-5092", "CVE-2018-5093", "CVE-2018-5094",
                "CVE-2018-5095", "CVE-2018-5097", "CVE-2018-5098", "CVE-2018-5099",
                "CVE-2018-5100", "CVE-2018-5101", "CVE-2018-5102", "CVE-2018-5103",
                "CVE-2018-5104", "CVE-2018-5105", "CVE-2018-5106", "CVE-2018-5107",
                "CVE-2018-5108", "CVE-2018-5109", "CVE-2018-5110", "CVE-2018-5111",
                "CVE-2018-5112", "CVE-2018-5113", "CVE-2018-5114", "CVE-2018-5115",
                "CVE-2018-5116", "CVE-2018-5117", "CVE-2018-5118", "CVE-2018-5119",
                "CVE-2018-5121", "CVE-2018-5122", "CVE-2018-5090", "CVE-2018-5089");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-25 17:28:00 +0000 (Mon, 25 Jun 2018)");
  script_tag(name:"creation_date", value:"2018-01-24 12:35:29 +0530 (Wed, 24 Jan 2018)");
  script_name("Mozilla Firefox Security Advisories (MFSA2018-02, MFSA2018-03) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple Use-after-free errors, buffer overflow errors, memory safety bugs
    and integer overflow errors.

  - WebExtensions can save and execute files on local file system without user prompts.

  - Developer Tools can expose style editor information cross-origin through service worker.

  - Printing process will follow symlinks for local file access.

  - Manually entered blob URL can be accessed by subsequent private browsing tabs.

  - Audio capture prompts and starts with incorrect origin attribution.

  - Cursor can be made invisible on OS X.

  - URL spoofing in addressbar through drag and drop.

  - Extension development tools panel can open a non-relative URL in the panel.

  - WebExtensions can load non-HTTPS pages with browser.identity.launchWebAuthFlow.

  - The old value of a cookie changed to HttpOnly remains accessible to scripts.

  - Background network requests can open HTTP authentication in unrelated foreground tabs.

  - WebExtension ActiveTab permission allows cross-origin frame content access.

  - URL spoofing with right-to-left text aligned left-to-right.

  - Activity Stream images can attempt to load local content through file:.

  - Reader view will load cross-origin content in violation of CORS headers.

  - OS X Tibetan characters render incompletely in the addressbar.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow remote attackers to execute arbitrary code on affected system or
  conduct a denial-of-service condition, gain escalated privileges, gain access
  to sensitive data, conduct phishing attacks, make use of old cookie value,
  get cross-origin frame content access, conduct spoofing and domain name spoofing
  attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox versions before 58.");

  script_tag(name:"solution", value:"Update to version 58 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-02/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"58")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"58", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
