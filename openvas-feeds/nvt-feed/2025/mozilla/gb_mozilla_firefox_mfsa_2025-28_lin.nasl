# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.28");
  script_cve_id("CVE-2025-2817", "CVE-2025-4083", "CVE-2025-4085", "CVE-2025-4087", "CVE-2025-4088", "CVE-2025-4089", "CVE-2025-4091", "CVE-2025-4092");
  script_tag(name:"creation_date", value:"2025-04-29 15:30:17 +0000 (Tue, 29 Apr 2025)");
  script_version("2025-04-30T05:39:51+0000");
  script_tag(name:"last_modification", value:"2025-04-30 05:39:51 +0000 (Wed, 30 Apr 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-28) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-28");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-28/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1924108%2C1950780%2C1959367");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1949994%2C1956698%2C1960198");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1951161%2C1952105");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1915280");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1917536");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1952465");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1953521");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1958350");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-2817: Privilege escalation in Firefox Updater
Mozilla Firefox's update mechanism allowed a medium-integrity user process to interfere with the SYSTEM-level updater by manipulating the file-locking behavior. By injecting code into the user-privileged process, an attacker could bypass intended access controls, allowing SYSTEM-level file operations on paths controlled by a non-privileged user and enabling privilege escalation.

CVE-2025-4083: Process isolation bypass using 'javascript:' URI links in cross-origin frames

A process isolation vulnerability in Firefox stemmed from improper handling of javascript: URIs, which could allow content to execute in the top-level document's process instead of the intended frame, potentially enabling a sandbox escape.

CVE-2025-4085: Potential information leakage and privilege escalation in UITour actor
An attacker with control over a content process could potentially leverage the privileged UITour actor to leak sensitive information or escalate privileges.

CVE-2025-4087: Unsafe attribute access during XPath parsing
A vulnerability was identified in Firefox where XPath parsing could trigger undefined behavior due to missing null checks during attribute access. This could lead to out-of-bounds read access and potentially, memory corruption.

CVE-2025-4088: Cross-site request forgery via storage access API redirects
A security vulnerability in Firefox allowed malicious sites to use redirects to send credentialed requests to arbitrary endpoints on any site that had invoked the Storage Access API. This enabled potential Cross-Site Request Forgery attacks across origins.

CVE-2025-4089: Potential local code execution in 'copy as cURL' command
Due to insufficient escaping of special characters in the 'copy as cURL' feature, an attacker could trick a user into using this command, potentially leading to local code execution on the user's system.

CVE-2025-4091: Memory safety bugs fixed in Firefox 138, Thunderbird 138, Firefox ESR 128.10, and Thunderbird 128.10
Memory safety bugs present in Firefox 137, Thunderbird ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 138.");

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

if (version_is_less(version: version, test_version: "138")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "138", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
