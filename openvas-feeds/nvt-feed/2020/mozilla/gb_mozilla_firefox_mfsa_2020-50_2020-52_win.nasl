# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817841");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2020-26951", "CVE-2020-26952", "CVE-2020-16012", "CVE-2020-26953",
                "CVE-2020-26954", "CVE-2020-26955", "CVE-2020-26956", "CVE-2020-26957",
                "CVE-2020-26958", "CVE-2020-26959", "CVE-2020-26960", "CVE-2020-26968",
                "CVE-2020-26961", "CVE-2020-26962", "CVE-2020-26963", "CVE-2020-26969",
                "CVE-2020-26965", "CVE-2020-26966", "CVE-2020-26967");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-09 20:08:00 +0000 (Wed, 09 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-11-18 18:10:44 +0530 (Wed, 18 Nov 2020)");
  script_name("Mozilla Firefox Security Advisories (MFSA2020-50, MFSA2020-52) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Parsing mismatches could confuse and bypass security sanitizer for chrome privileged code.

  - Out of memory handling of JITed, inlined functions could lead to a memory corruption.

  - Variable time processing of cross-origin images during drawImage calls.

  - Fullscreen could be enabled without displaying the security UI.

  - Local spoofing of web manifests for arbitrary pages in Firefox for Android.

  - XSS through paste (manual and clipboard API).

  - OneCRL was not working in Firefox for Android.

  - Requests intercepted through ServiceWorkers lacked MIME type restrictions.

  - Use-after-free in WebRequestService.

  - Potential use-after-free in uses of nsTArray.

  - Heap buffer overflow in freetype.

  - DoH did not filter IPv4 mapped IP Addresses.

  - Cross-origin iframes supported login autofill.

  - History and Location interfaces could have been used to hang the browser.

  - Software keyboards may have remembered typed passwords.

  - Single-word search queries were also broadcast to local network.

  - Mutation Observers could break or confuse Firefox Screenshots feature.

  - Memory safety bugs fixed.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass security, disclose sensitive information and run arbitrary code");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  83 on Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox version 83
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-50/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"83")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"83", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
