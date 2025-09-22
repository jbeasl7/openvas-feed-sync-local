# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.01");
  script_cve_id("CVE-2024-43097", "CVE-2025-0237", "CVE-2025-0238", "CVE-2025-0239", "CVE-2025-0240", "CVE-2025-0241", "CVE-2025-0242", "CVE-2025-0243", "CVE-2025-0247");
  script_tag(name:"creation_date", value:"2025-01-08 07:06:37 +0000 (Wed, 08 Jan 2025)");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-01) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-01");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-01/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1827142%2C1932783");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1835193%2C1910021%2C1919803%2C1931576%2C1931948%2C1932173");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1874523%2C1926454%2C1931873%2C1932169");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1915257");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1915535");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1929156");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1929623");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1933023");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1945624");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-43097: Overflow when growing an SkRegion's RunArray
In resizeToAtLeast of SkRegion.cpp, there was a possible out of bounds write due to an integer overflow

CVE-2025-0237: WebChannel APIs susceptible to confused deputy attack
The WebChannel API, which is used to transport various information across processes, did not check the sending principal but rather accepted the principal being sent. This could have led to privilege escalation attacks.

CVE-2025-0238: Use-after-free when breaking lines in text
Assuming a controlled failed memory allocation, an attacker could have caused a use-after-free, leading to a potentially exploitable crash.

CVE-2025-0239: Alt-Svc ALPN validation failure when redirected
When using Alt-Svc, ALPN did not properly validate certificates when the original server is redirecting to an insecure site.

CVE-2025-0240: Compartment mismatch when parsing JavaScript JSON module
Parsing a JavaScript module as JSON could, under some circumstances, cause cross-compartment access, which may result in a use-after-free.

CVE-2025-0241: Memory corruption when using JavaScript Text Segmentation
When segmenting specially crafted text, segmentation would corrupt memory leading to a potentially exploitable crash.

CVE-2025-0242: Memory safety bugs fixed in Firefox 134, Thunderbird 134, Firefox ESR 115.19, Firefox ESR 128.6, Thunderbird 115.19, and Thunderbird 128.6
Memory safety bugs present in Firefox 133, Thunderbird 133, Firefox ESR 115.18, Firefox ESR 128.5, Thunderbird 115.18, and Thunderbird 128.5. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2025-0243: Memory safety bugs fixed in Firefox 134, Thunderbird 134, Firefox ESR 128.6, and Thunderbird 128.6
Memory safety bugs present in Firefox 133, Thunderbird 133, Firefox ESR 128.5, and Thunderbird 128.5. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2025-0247: Memory safety bugs fixed in Firefox 134 and Thunderbird 134
Memory safety bugs present in Firefox 133 and Thunderbird 133. Some of these bugs showed evidence of memory corruption and ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 134.");

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

if (version_is_less(version: version, test_version: "134")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "134", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
