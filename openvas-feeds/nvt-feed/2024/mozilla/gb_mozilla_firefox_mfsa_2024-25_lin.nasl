# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2024.25");
  script_cve_id("CVE-2024-5688", "CVE-2024-5689", "CVE-2024-5690", "CVE-2024-5691", "CVE-2024-5693", "CVE-2024-5694", "CVE-2024-5695", "CVE-2024-5696", "CVE-2024-5697", "CVE-2024-5698", "CVE-2024-5699", "CVE-2024-5700", "CVE-2024-5701");
  script_tag(name:"creation_date", value:"2024-06-11 15:12:51 +0000 (Tue, 11 Jun 2024)");
  script_version("2024-09-16T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-16 05:05:46 +0000 (Mon, 16 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-13 18:31:42 +0000 (Fri, 13 Sep 2024)");

  script_name("Mozilla Firefox Security Advisory (MFSA2024-25) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2024-25");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-25/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1862809%2C1889355%2C1893388%2C1895123");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1890909%2C1891422%2C1893915%2C1894047%2C1896024");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1389707");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1414937");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1828259");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1883693");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1888695");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1891319");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1891349");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1895055");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1895086");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1895579");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1896555");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-5688: Use-after-free in JavaScript object transplant
If a garbage collection was triggered at the right time, a use-after-free could have occurred during object transplant.

CVE-2024-5689: User confusion and possible phishing vector via Firefox Screenshots
In addition to detecting when a user was taking a screenshot (XXX), a website was able to overlay the 'My Shots' button that appeared, and direct the user to a replica Firefox Screenshots page that could be used for phishing.

CVE-2024-5690: External protocol handlers leaked by timing attack
By monitoring the time certain operations take, an attacker could have guessed which external protocol handlers were functional on a user's system.

CVE-2024-5691: Sandboxed iframes were able to bypass sandbox restrictions to open a new window
By tricking the browser with a X-Frame-Options header, a sandboxed iframe could have presented a button that, if clicked by a user, would bypass restrictions to open a new window.

CVE-2024-5693: Cross-Origin Image leak via Offscreen Canvas
Offscreen Canvas did not properly track cross-origin tainting, which could be used to access image data from another site in violation of same-origin policy.

CVE-2024-5694: Use-after-free in JavaScript Strings
An attacker could have caused a use-after-free in the JavaScript engine to read memory in the JavaScript string section of the heap.

CVE-2024-5695: Memory Corruption using allocation using out-of-memory conditions
If an out-of-memory condition occurs at a specific point using allocations in the probabilistic heap checker, an assertion could have been triggered, and in rarer situations, memory corruption could have occurred.

CVE-2024-5696: Memory Corruption in Text Fragments
By manipulating the text in an <input> tag, an attacker could have caused corrupt memory leading to a potentially exploitable crash.

CVE-2024-5697: Website was able to detect when Firefox was taking a screenshot of them
A website was able to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 127.");

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

if (version_is_less(version: version, test_version: "127")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "127", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
