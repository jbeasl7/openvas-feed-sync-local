# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2024.55");
  script_cve_id("CVE-2024-10458", "CVE-2024-10459", "CVE-2024-10460", "CVE-2024-10461", "CVE-2024-10462", "CVE-2024-10463", "CVE-2024-10464", "CVE-2024-10465", "CVE-2024-10466", "CVE-2024-10467", "CVE-2024-10468");
  script_tag(name:"creation_date", value:"2024-10-29 15:50:44 +0000 (Tue, 29 Oct 2024)");
  script_version("2024-11-06T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-11-06 05:05:44 +0000 (Wed, 06 Nov 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-04 13:26:32 +0000 (Mon, 04 Nov 2024)");

  script_name("Mozilla Firefox Security Advisory (MFSA2024-55) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2024-55");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-55/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1829029%2C1888538%2C1900394%2C1904059%2C1917742%2C1919809%2C1923706");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1912537");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1913000");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1914521");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1914982");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1918853");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1919087");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1920423");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1920800");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1921733");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1924154");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-10458: Permission leak via embed or object elements
A permission leak could have occurred from a trusted site to an untrusted site via embed or object elements.

CVE-2024-10459: Use-after-free in layout with accessibility
An attacker could have caused a use-after-free when accessibility was enabled, leading to a potentially exploitable crash.

CVE-2024-10460: Confusing display of origin for external protocol handler prompt
The origin of an external protocol handler prompt could have been obscured using a data: URL within an iframe.

CVE-2024-10461: XSS due to Content-Disposition being ignored in multipart/x-mixed-replace response
In multipart/x-mixed-replace responses, Content-Disposition: attachment in the response header was not respected and did not force a download, which could allow XSS attacks.

CVE-2024-10462: Origin of permission prompt could be spoofed by long URL
Truncation of a long URL could have allowed origin spoofing in a permission prompt.

CVE-2024-10463: Cross origin video frame leak
Video frames could have been leaked between origins in some situations.

CVE-2024-10468: Race conditions in IndexedDB
Potential race conditions in IndexedDB could have caused memory corruption, leading to a potentially exploitable crash.

CVE-2024-10464: History interface could have been used to cause a Denial of Service condition in the browser
Repeated writes to history interface attributes could have been used to cause a Denial of Service condition in the browser. This was addressed by introducing rate-limiting to this API.

CVE-2024-10465: Clipboard 'paste' button persisted across tabs
A clipboard 'paste' button could persist across tabs which allowed a spoofing attack.

CVE-2024-10466: DOM push subscription message could hang Firefox
By sending a specially crafted push message, a remote server could have hung the parent process, causing the browser to become unresponsive.

CVE-2024-10467: Memory safety bugs fixed in Firefox 132, Thunderbird 132, Firefox ESR 128.4, and Thunderbird 128.4
Memory safety bugs present in Firefox 131, Firefox ESR 128.3, and Thunderbird 128.3. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 132.");

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

if (version_is_less(version: version, test_version: "132")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "132", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
