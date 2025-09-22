# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2024.29");
  script_cve_id("CVE-2024-6601", "CVE-2024-6602", "CVE-2024-6603", "CVE-2024-6604", "CVE-2024-6606", "CVE-2024-6607", "CVE-2024-6608", "CVE-2024-6609", "CVE-2024-6610", "CVE-2024-6611", "CVE-2024-6612", "CVE-2024-6613", "CVE-2024-6614", "CVE-2024-6615", "CVE-2024-7652", "CVE-2024-43357");
  script_tag(name:"creation_date", value:"2024-07-10 07:44:56 +0000 (Wed, 10 Jul 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-29 18:32:56 +0000 (Thu, 29 Aug 2024)");

  script_name("Mozilla Firefox Security Advisory (MFSA2024-29) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2024-29");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-29/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1748105%2C1837550%2C1884266");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1892875%2C1894428%2C1898364");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1694513");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1743329");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1839258");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1844827");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1880374");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1883396");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1890748");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1895032");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1895081");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1900523");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1901411");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1902305");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1902983");
  script_xref(name:"URL", value:"https://github.com/tc39/ecma262/security/advisories/GHSA-g38c-wh3c-5h9r");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-7652: Type Confusion in Async Generators in Javascript Engine
An error in the ECMA-262 specification relating to Async Generators could have resulted in a type confusion, potentially leading to memory corruption and an exploitable crash.

CVE-2024-6606: Out-of-bounds read in clipboard component
Clipboard code failed to check the index on an array access. This could have led to an out-of-bounds read.

CVE-2024-6607: Leaving pointerlock by pressing the escape key could be prevented
It was possible to prevent a user from exiting pointerlock when pressing
escape
and to overlay customValidity notifications from a <select> element over certain
permission prompts. This could be used to confuse a user into giving a site unintended permissions.

CVE-2024-6608: Cursor could be moved out of the viewport using pointerlock.
It was possible to move the cursor using pointerlock from an iframe. This allowed moving the cursor outside of the viewport and the Firefox window.

CVE-2024-6609: Memory corruption in NSS
When almost out-of-memory an elliptic curve key which was never allocated could have been freed again.

CVE-2024-6610: Form validation popups could block exiting full-screen mode
Form validation popups could capture escape key presses. Therefore, spamming form validation messages could be used to prevent users from exiting full-screen mode.

CVE-2024-6601: Race condition in permission assignment
A race condition could lead to a cross-origin container obtaining permissions of the top-level origin.

CVE-2024-6602: Memory corruption in NSS
A mismatch between allocator and deallocator could have led to memory corruption.

CVE-2024-6603: Memory corruption in thread creation
In an out-of-memory scenario an allocation could fail but free would have been called on the pointer afterwards leading to memory corruption.

CVE-2024-6611: Incorrect handling of SameSite cookies
A nested iframe, triggering a cross-site navigation, could send SameSite=Strict or Lax cookies.

CVE-2024-6612: CSP violation leakage when using devtools
CSP violations generated links in the console tab of the developer tools, pointing to the violating resource. This caused a DNS prefetch which leaked that a CSP violation happened.

CVE-2024-6613: Incorrect listing of stack frames
The frame iterator could get stuck in a loop when encountering certain wasm frames leading to incorrect stack traces.

CVE-2024-6614: Incorrect listing of stack frames
The frame iterator could get stuck in a loop when ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 128.");

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

if (version_is_less(version: version, test_version: "128")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "128", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
