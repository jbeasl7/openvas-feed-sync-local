# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2024.18");
  script_cve_id("CVE-2024-3302", "CVE-2024-3852", "CVE-2024-3853", "CVE-2024-3854", "CVE-2024-3855", "CVE-2024-3856", "CVE-2024-3857", "CVE-2024-3858", "CVE-2024-3859", "CVE-2024-3860", "CVE-2024-3861", "CVE-2024-3862", "CVE-2024-3864", "CVE-2024-3865", "CVE-2024-5702");
  script_tag(name:"creation_date", value:"2024-04-18 11:57:25 +0000 (Thu, 18 Apr 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2024-18) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2024-18");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-18/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1881076%2C1884887%2C1885359%2C1889049");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1193389");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1874489");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1881183");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1881417");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1883158");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1883542");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1884427");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1884457");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1884552");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1885828");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1885829");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1886683");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1888333");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1888892");
  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/421644");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-3852: GetBoundName in the JIT returned the wrong object
GetBoundName could return the wrong version of an object when JIT optimizations were applied.

CVE-2024-5702: Use-after-free in networking
Memory corruption in the networking stack could have led to a potentially exploitable crash.

CVE-2024-3853: Use-after-free if garbage collection runs during realm initialization
A use-after-free could result if a JavaScript realm was in the process of being initialized when a garbage collection started.

CVE-2024-3854: Out-of-bounds-read after mis-optimized switch statement
In some code patterns the JIT incorrectly optimized switch statements and generated code with out-of-bounds-reads.

CVE-2024-3855: Incorrect JIT optimization of MSubstr leads to out-of-bounds reads
In certain cases the JIT incorrectly optimized MSubstr operations, which led to out-of-bounds reads.

CVE-2024-3856: Use-after-free in WASM garbage collection
A use-after-free could occur during WASM execution if garbage collection ran during the creation of an array.

CVE-2024-3857: Incorrect JITting of arguments led to use-after-free during garbage collection
The JIT created incorrect code for arguments in certain cases. This led to potential use-after-free crashes during garbage collection.

CVE-2024-3858: Corrupt pointer dereference in js::CheckTracedThing<js::Shape>
It was possible to mutate a JavaScript object so that the JIT could crash while tracing it.

CVE-2024-3859: Integer-overflow led to out-of-bounds-read in the OpenType sanitizer
On 32-bit versions there were integer-overflows that led to an out-of-bounds-read that potentially could be triggered by a malformed OpenType font.

CVE-2024-3860: Crash when tracing empty shape lists
An out-of-memory condition during object initialization could result in an empty shape list. If the JIT subsequently traced the object it would crash.

CVE-2024-3861: Potential use-after-free due to AlignedBuffer self-move
If an AlignedBuffer were assigned to itself, the subsequent self-move could result in an incorrect reference count and later use-after-free.

CVE-2024-3862: Potential use of uninitialized memory in MarkStack assignment operator on self-assignment
The MarkStack assignment operator, part of the JavaScript engine, could access uninitialized memory if it were used in a self-assignment.

CVE-2024-3302: Denial of Service using HTTP/2 CONTINUATION frames
There was no limit to the number of HTTP/2 CONTINUATION frames that would be processed. A server could abuse this to create an Out of Memory condition in the browser.

CVE-2024-3864: Memory safety bug fixed in Firefox 125, Firefox ESR 115.10, and ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 125.");

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

if (version_is_less(version: version, test_version: "125")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "125", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
