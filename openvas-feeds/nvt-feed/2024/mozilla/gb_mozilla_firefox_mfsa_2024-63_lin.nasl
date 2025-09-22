# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2024.63");
  script_cve_id("CVE-2024-11692", "CVE-2024-11694", "CVE-2024-11695", "CVE-2024-11696", "CVE-2024-11697", "CVE-2024-11699", "CVE-2024-11701", "CVE-2024-11704", "CVE-2024-11705", "CVE-2024-11706", "CVE-2024-11708");
  script_tag(name:"creation_date", value:"2024-11-26 16:24:00 +0000 (Tue, 26 Nov 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mozilla Firefox Security Advisory (MFSA2024-63) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2024-63");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-63/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1880582%2C1929911");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1842187");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1899402");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1909535");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1914797");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1921768");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1922912");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1923767");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1924167");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1925496");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1929600");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-11692: Select list elements could be shown over another site
An attacker could cause a select dropdown to be shown over another tab, this could have led to user confusion and possible spoofing attacks.

CVE-2024-11701: Misleading Address Bar State During Navigation Interruption
The incorrect domain may have been displayed in the address bar during an interrupted navigation attempt. This could have led to user confusion and possible spoofing attacks.

CVE-2024-11694: CSP Bypass and XSS Exposure via Web Compatibility Shims
Enhanced Tracking Protection's Strict mode may have inadvertently allowed a CSP frame-src bypass and DOM-based XSS through the Google SafeFrame shim in the Web Compatibility extension. This issue could have exposed users to malicious frames masquerading as legitimate content.

CVE-2024-11695: URL Bar Spoofing via Manipulated Punycode and Whitespace Characters
A crafted URL containing Arabic script and whitespace characters could have hidden the true origin of the page, resulting in a potential spoofing attack.

CVE-2024-11696: Unhandled Exception in Add-on Signature Verification
The application failed to account for exceptions thrown by the loadManifestFromFile method during add-on signature verification. This flaw, triggered by an invalid or unsupported extension manifest, could have caused runtime errors that disrupted the signature validation process. As a result, the enforcement of signature validation for unrelated add-ons may have been bypassed. Signature validation in this context is used to ensure that third-party applications on the user's ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 133.");

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

if (version_is_less(version: version, test_version: "133")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "133", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
