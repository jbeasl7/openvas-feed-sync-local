# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2024.21");
  script_cve_id("CVE-2024-10941", "CVE-2024-4367", "CVE-2024-4764", "CVE-2024-4767", "CVE-2024-4768", "CVE-2024-4769", "CVE-2024-4770", "CVE-2024-4771", "CVE-2024-4772", "CVE-2024-4773", "CVE-2024-4774", "CVE-2024-4775", "CVE-2024-4776", "CVE-2024-4777", "CVE-2024-4778");
  script_tag(name:"creation_date", value:"2024-05-15 10:08:57 +0000 (Wed, 15 May 2024)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-22 16:42:03 +0000 (Wed, 22 Jan 2025)");

  script_name("Mozilla Firefox Security Advisory (MFSA2024-21) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2024-21");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-21/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1838834%2C1889291%2C1889595%2C1890204%2C1891545");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1878199%2C1893340");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1870579");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1875248");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1878577");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1879093");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1880879");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1886082");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1886108");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1886598");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1887332");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1887343");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1887614");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1893270");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1893645");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1893891");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-4764: Use-after-free when audio input connected with multiple consumers
Multiple WebRTC threads could have claimed a newly connected audio input leading to use-after-free.

CVE-2024-4367: Arbitrary JavaScript execution in PDF.js
A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context.

CVE-2024-4767: IndexedDB files retained in private browsing mode
If the browser.privatebrowsing.autostart preference is enabled, IndexedDB files were not properly deleted when the window was closed. This preference is disabled by default in Firefox.

CVE-2024-4768: Potential permissions request bypass via clickjacking
A bug in popup notifications' interaction with WebAuthn made it easier for an attacker to trick a user into granting permissions.

CVE-2024-4769: Cross-origin responses could be distinguished between script and non-script content-types
When importing resources using Web Workers, error messages would distinguish the difference between application/javascript responses and non-script responses. This could have been abused to learn information cross-origin.

CVE-2024-4770: Use-after-free could occur when printing to PDF
When saving a page to PDF, certain font styles could have led to a potential use-after-free crash.

CVE-2024-4771: Failed allocation could lead to use-after-free
A memory allocation check was missing which would lead to a use-after-free if the allocation failed. This could have triggered a crash or potentially be leveraged to achieve code execution.

CVE-2024-4772: Use of insecure rand() function to generate nonce
An HTTP digest authentication nonce value was generated using rand() which could lead to predictable values.

CVE-2024-4773: URL bar could be cleared after network error
When a network error occurred during page load, the prior content could have remained in view with a blank URL bar. This could have been used to obfuscate a spoofed web site.

CVE-2024-4774: Undefined behavior in ShmemCharMapHashEntry()
The ShmemCharMapHashEntry() code was susceptible to potentially undefined behavior by bypassing the move semantics for one of its data ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 126.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "126")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "126", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
