# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.07");
  script_cve_id("CVE-2025-1009", "CVE-2025-1010", "CVE-2025-1011", "CVE-2025-1012", "CVE-2025-1013", "CVE-2025-1014", "CVE-2025-1016", "CVE-2025-1017", "CVE-2025-1018", "CVE-2025-1019", "CVE-2025-1020");
  script_tag(name:"creation_date", value:"2025-02-07 09:01:44 +0000 (Fri, 07 Feb 2025)");
  script_version("2025-02-07T15:39:36+0000");
  script_tag(name:"last_modification", value:"2025-02-07 15:39:36 +0000 (Fri, 07 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-06 19:40:45 +0000 (Thu, 06 Feb 2025)");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-07) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-07");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-07/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1926256%2C1935984%2C1935471");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1936601%2C1936844%2C1937694%2C1938469%2C1939583%2C1940994");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1939063%2C1942169");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1910818");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1932555");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1936454");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1936613");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1936982");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1939710");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1940162");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1940804");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-1009: Use-after-free in XSLT
An attacker could have caused a use-after-free via crafted XSLT data, leading to a potentially exploitable crash.

CVE-2025-1010: Use-after-free in Custom Highlight
An attacker could have caused a use-after-free via the Custom Highlight API, leading to a potentially exploitable crash.

CVE-2025-1018: Fullscreen notification is not displayed when fullscreen is re-requested
The fullscreen notification is prematurely hidden when fullscreen is re-requested quickly by the user. This could have been leveraged to perform a potential spoofing attack.

CVE-2025-1011: A bug in WebAssembly code generation could result in a crash
A bug in WebAssembly code generation could have lead to a crash. It may have been possible for an attacker to leverage this to achieve code execution.

CVE-2025-1012: Use-after-free during concurrent delazification
A race during concurrent delazification could have led to a use-after-free.

CVE-2025-1019: Fullscreen notification not properly displayed
The z-order of the browser windows could be manipulated to hide the fullscreen notification. This could potentially be leveraged to perform a spoofing attack.

CVE-2025-1013: Potential opening of private browsing tabs in normal browsing windows
A race condition could have led to private browsing tabs being opened in normal browsing windows. This could have resulted in a potential privacy leak.

CVE-2025-1014: Certificate length was not properly checked
Certificate length was not properly checked when added to a certificate store. In practice only trusted data was processed.

CVE-2025-1016: Memory safety bugs fixed in Firefox 135, Thunderbird 135, Firefox ESR 115.20, Firefox ESR 128.7, Thunderbird 115.20, and Thunderbird 128.7
Memory safety bugs present in Firefox 134, Thunderbird 134, Firefox ESR 115.19, Firefox ESR 128.6, Thunderbird 115.19, and Thunderbird 128.6. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2025-1017: Memory safety bugs fixed in Firefox 135, Thunderbird 135, Firefox ESR 128.7, and Thunderbird 128.7
Memory safety bugs present in Firefox 134, Thunderbird 134, Firefox ESR 128.6, and Thunderbird 128.6. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2025-1020: Memory safety bugs fixed in Firefox 135 and Thunderbird 135
Memory safety bugs present in Firefox 134 and Thunderbird 134. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 135.");

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

if (version_is_less(version: version, test_version: "135")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "135", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
