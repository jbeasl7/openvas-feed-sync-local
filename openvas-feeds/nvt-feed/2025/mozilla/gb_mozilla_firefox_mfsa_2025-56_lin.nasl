# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.56");
  script_cve_id("CVE-2025-8027", "CVE-2025-8028", "CVE-2025-8029", "CVE-2025-8030", "CVE-2025-8031", "CVE-2025-8032", "CVE-2025-8033", "CVE-2025-8034", "CVE-2025-8035", "CVE-2025-8036", "CVE-2025-8037", "CVE-2025-8038", "CVE-2025-8039", "CVE-2025-8040", "CVE-2025-8044");
  script_tag(name:"creation_date", value:"2025-07-22 14:45:38 +0000 (Tue, 22 Jul 2025)");
  script_version("2025-07-23T05:44:58+0000");
  script_tag(name:"last_modification", value:"2025-07-23 05:44:58 +0000 (Wed, 23 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-56) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-56");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-56/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1933572%2C1971116");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1970422%2C1970422%2C1970422%2C1970422");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1975058%2C1975058%2C1975998%2C1975998");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1975961%2C1975961%2C1975961");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1808979");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1928021");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1960834");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1964767");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1968414");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1968423");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1970997");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1971581");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1971719");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1973990");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1974407");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-8027: JavaScript engine only wrote partial return value to stack
On 64-bit platforms IonMonkey-JIT only wrote 32 bits of the 64-bit return value space on the stack. Baseline-JIT, however, read the entire 64 bits.

CVE-2025-8028: Large branch table could lead to truncated instruction
On arm64, a WASM br_table instruction with a lot of entries could lead to the label being too far from the instruction causing truncation and incorrect computation of the branch address.

CVE-2025-8029: javascript: URLs executed on object and embed tags
Firefox executed javascript: URLs when used in object and embed tags.

CVE-2025-8036: DNS rebinding circumvents CORS
Firefox cached CORS preflight responses across IP address changes. This allowed circumventing CORS with DNS rebinding.

CVE-2025-8037: Nameless cookies shadow secure cookies
Setting a nameless cookie with an equals sign in the value shadowed other cookies. Even if the nameless cookie was set over HTTP and the shadowed cookie included the Secure attribute.

CVE-2025-8030: Potential user-assisted code execution in 'Copy as cURL' command
Insufficient escaping in the 'Copy as cURL' feature could potentially be used to trick a user into executing unexpected code.

CVE-2025-8031: Incorrect URL stripping in CSP reports
The username:password part was not correctly stripped from URLs in CSP reports potentially leaking HTTP Basic Authentication credentials.

CVE-2025-8032: XSLT documents could bypass CSP
XSLT document loading did not correctly propagate the source document which bypassed its CSP.

CVE-2025-8038: CSP frame-src was not correctly enforced for paths
Firefox ignored paths when checking the validity of navigations in a frame.

CVE-2025-8039: Search terms persisted in URL bar
In some cases search terms persisted in the URL bar even after navigating away from the search page.

CVE-2025-8033: Incorrect JavaScript state machine for generators
The JavaScript engine did not handle closed generators correctly and it was possible to resume them leading to a nullptr deref.

CVE-2025-8044: Memory safety bugs fixed in Firefox 141 and Thunderbird 141
Memory safety bugs present in Firefox 140 and Thunderbird 140. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2025-8034: Memory safety bugs fixed in Firefox ESR 115.26, Firefox ESR 128.13, Thunderbird ESR ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 141.");

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

if (version_is_less(version: version, test_version: "141")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "141", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
