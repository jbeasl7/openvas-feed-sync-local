# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.20");
  script_cve_id("CVE-2025-3028", "CVE-2025-3029", "CVE-2025-3030", "CVE-2025-3031", "CVE-2025-3032", "CVE-2025-3034", "CVE-2025-3035");
  script_tag(name:"creation_date", value:"2025-04-02 07:16:10 +0000 (Wed, 02 Apr 2025)");
  script_version("2025-04-03T05:39:15+0000");
  script_tag(name:"last_modification", value:"2025-04-03 05:39:15 +0000 (Thu, 03 Apr 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-20) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-20");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-20/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1850615%2C1932468%2C1942551%2C1951017%2C1951494");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1894100%2C1934086%2C1950360");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1941002");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1947141");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1949987");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1952213");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1952268");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-3028: Use-after-free triggered by XSLTProcessor
JavaScript code running while transforming a document with the XSLTProcessor could lead to a use-after-free.

CVE-2025-3031: JIT optimization bug with different stack slot sizes
An attacker could read 32 bits of values spilled onto the stack in a JIT compiled function.

CVE-2025-3032: Leaking file descriptors from the fork server
Leaking of file descriptors from the fork server to web content processes could allow for privilege escalation attacks.

CVE-2025-3029: URL bar spoofing via non-BMP Unicode characters
A crafted URL containing specific Unicode characters could have hidden the true origin of the page, resulting in a potential spoofing attack.

CVE-2025-3035: Tab title disclosure across pages when using AI chatbot
By first using the AI chatbot in one tab and later activating it in another tab, the document title of the previous tab would leak into the chat prompt.

CVE-2025-3030: Memory safety bugs fixed in Firefox 137, Thunderbird 137, Firefox ESR 128.9, and Thunderbird 128.9
Memory safety bugs present in Firefox 136, Thunderbird 136, Firefox ESR 128.8, and Thunderbird 128.8. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2025-3034: Memory safety bugs fixed in Firefox 137 and Thunderbird 137
Memory safety bugs present in Firefox 136 and Thunderbird 136. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 137.");

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

if (version_is_less(version: version, test_version: "137")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "137", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
