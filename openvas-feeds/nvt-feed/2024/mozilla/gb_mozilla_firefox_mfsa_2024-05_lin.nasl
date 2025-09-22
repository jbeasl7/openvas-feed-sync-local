# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2024.05");
  script_cve_id("CVE-2024-1546", "CVE-2024-1547", "CVE-2024-1548", "CVE-2024-1549", "CVE-2024-1550", "CVE-2024-1551", "CVE-2024-1552", "CVE-2024-1553", "CVE-2024-1554", "CVE-2024-1555", "CVE-2024-1556", "CVE-2024-1557");
  script_tag(name:"creation_date", value:"2024-02-21 13:15:21 +0000 (Wed, 21 Feb 2024)");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-10 17:46:14 +0000 (Tue, 10 Dec 2024)");

  script_name("Mozilla Firefox Security Advisory (MFSA2024-05) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2024-05");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-05/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1746471%2C1848829%2C1864011%2C1869175%2C1869455%2C1869938%2C1871606");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1855686%2C1867982%2C1871498%2C1872296%2C1873521%2C1873577%2C1873597%2C1873866%2C1874080%2C1874740%2C1875795%2C1875906%2C1876425%2C1878211%2C1878286");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1816390");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1832627");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1833814");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1843752");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1860065");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1864385");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1870414");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1873223");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1874502");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1877879");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-1546: Out-of-bounds memory read in networking channels
When storing and re-accessing data on a networking channel, the length of buffers may have been confused, resulting in an out-of-bounds memory read.

CVE-2024-1547: Alert dialog could have been spoofed on another site
Through a series of API calls and redirects, an attacker-controlled alert dialog could have been displayed on another website (with the victim website's URL shown).

CVE-2024-1554: fetch could be used to effect cache poisoning
The fetch() API and navigation incorrectly shared the same cache, as the cache key did not include the optional headers fetch() may contain. Under the correct circumstances, an attacker may have been able to poison the local browser cache by priming it with a fetch() response controlled by the additional headers. Upon navigation to the same URL, the user would see the cached response instead of the expected response.

CVE-2024-1548: Fullscreen Notification could have been hidden by select element
A website could have obscured the fullscreen notification by using a dropdown select input element. This could have led to user confusion and possible spoofing attacks.

CVE-2024-1549: Custom cursor could obscure the permission dialog
If a website set a large custom cursor, portions of the cursor could have overlapped with the permission dialog, potentially resulting in user confusion and unexpected granted permissions.

CVE-2024-1550: Mouse cursor re-positioned unexpectedly could have led to unintended permission grants
A malicious website could have used a combination of exiting fullscreen mode and requestPointerLock to cause the user's mouse to be re-positioned unexpectedly, which could have led to user confusion and inadvertently granting permissions they did not intend to grant.

CVE-2024-1551: Multipart HTTP Responses would accept the Set-Cookie header in response parts
Set-Cookie response headers were being incorrectly honored in multipart HTTP responses. If an attacker could control the Content-Type response header, as well as control part of the response body, they could inject Set-Cookie response headers that would have been honored by the browser.

CVE-2024-1555: SameSite cookies were not properly respected when opening a website from an external browser
When opening a website using the firefox:// protocol handler, SameSite cookies were not properly respected.

CVE-2024-1556: Invalid memory access in the built-in profiler
The incorrect object was checked for NULL in the built-in profiler, potentially leading to invalid memory access and undefined behavior. Note: This issue only affects the application when the profiler is running.

CVE-2024-1552: Incorrect code generation on 32-bit ARM devices
Incorrect code generation could have led to unexpected numeric conversions and potential undefined behavior. Note: This issue only affects 32-bit ARM devices.

CVE-2024-1553: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 123.");

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

if (version_is_less(version: version, test_version: "123")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "123", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
