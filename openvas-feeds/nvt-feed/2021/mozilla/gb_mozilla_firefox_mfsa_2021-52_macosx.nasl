# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818881");
  script_cve_id("CVE-2021-4128", "CVE-2021-4129", "CVE-2021-43536", "CVE-2021-43537", "CVE-2021-43538", "CVE-2021-43539", "CVE-2021-43540", "CVE-2021-43541", "CVE-2021-43542", "CVE-2021-43543", "CVE-2021-43545", "CVE-2021-43546");
  script_tag(name:"creation_date", value:"2021-12-12 23:57:32 +0530 (Sun, 12 Dec 2021)");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-03 20:19:00 +0000 (Tue, 03 Jan 2023)");

  script_name("Mozilla Firefox Security Advisory (MFSA2021-52) - Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  script_xref(name:"Advisory-ID", value:"MFSA2021-52");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-52/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1393362%2C1736046%2C1736751%2C1737009%2C1739372%2C1739421");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1636629");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1696685");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1720926");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1723281");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1730120");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1735852");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1737751");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1738237");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1738418");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1739091");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1739683");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-43536: URL leakage when navigating while executing asynchronous function
Under certain circumstances, asynchronous functions could have caused a navigation to fail but expose the target URL.

CVE-2021-43537: Heap buffer overflow when using structured clone
An incorrect type conversion of sizes from 64bit to 32bit integers allowed an attacker to corrupt memory leading to a potentially exploitable crash.

CVE-2021-43538: Missing fullscreen and pointer lock notification when requesting both
By misusing a race in our notification code, an attacker could have forcefully hidden the notification for pages that had received full screen and pointer lock access, which could have been used for spoofing attacks.

CVE-2021-43539: GC rooting failure when calling wasm instance methods
Failure to correctly record the location of live pointers across wasm instance calls resulted in a GC occurring within the call not tracing those live pointers. This could have led to a use-after-free causing a potentially exploitable crash.

CVE-2021-4128: Use-after-free in fullscreen objects on macOS
When transitioning in and out of fullscreen mode, a graphics object was not correctly protected. This resulted in memory corruption and a potentially exploitable crash.
This bug only affects Firefox on Mac OS X. Other operating systems are unaffected.

CVE-2021-43540: WebExtensions could have installed persistent ServiceWorkers
WebExtensions with the correct permissions were able to create and install ServiceWorkers for third-party websites that would not have been uninstalled with the extension.

CVE-2021-43541: External protocol handler parameters were unescaped
When invoking protocol handlers for external protocols, a supplied parameter URL containing spaces was not properly escaped.

CVE-2021-43542: XMLHttpRequest error codes could have leaked the existence of an external protocol handler
Using XMLHttpRequest, an attacker could have identified installed applications by probing error messages for loading external protocols.

CVE-2021-43543: Bypass of CSP sandbox directive when embedding
Documents loaded with the CSP sandbox directive could have escaped the sandbox's script restriction by embedding additional content.

CVE-2021-43545: Denial of Service when using the Location API in a loop
Using the Location API in a loop could have caused severe application hangs and crashes.

CVE-2021-43546: Cursor spoofing could overlay user interface when native cursor is zoomed
It was possible to recreate previous cursor ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 95.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "95")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "95", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
