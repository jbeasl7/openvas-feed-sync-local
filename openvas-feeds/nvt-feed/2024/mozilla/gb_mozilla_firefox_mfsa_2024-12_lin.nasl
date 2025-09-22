# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2024.12");
  script_cve_id("CVE-2023-5388", "CVE-2024-2606", "CVE-2024-2607", "CVE-2024-2608", "CVE-2024-2609", "CVE-2024-2610", "CVE-2024-2611", "CVE-2024-2612", "CVE-2024-2613", "CVE-2024-2614", "CVE-2024-2615");
  script_tag(name:"creation_date", value:"2024-03-19 15:50:44 +0000 (Tue, 19 Mar 2024)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-25 14:48:08 +0000 (Tue, 25 Feb 2025)");

  script_name("Mozilla Firefox Security Advisory (MFSA2024-12) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2024-12");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-12/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1685358%2C1861016%2C1880405%2C1881093");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1881074%2C1882438%2C1881650");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1780432");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1866100");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1871112");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1875701");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1876675");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1879237");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1879444");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1879939");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1880692");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-2606: Mishandling of WASM register values
Passing invalid data could have led to invalid wasm values being created, such as arbitrary integers turning into pointer values.

CVE-2024-2607: JIT code failed to save return registers on Armv7-A
Return registers were overwritten which could have allowed an attacker to execute arbitrary code. Note: This issue only affected Armv7-A systems. Other operating systems are unaffected.

CVE-2024-2608: Integer overflow could have led to out of bounds write
AppendEncodedAttributeValue(), ExtraSpaceNeededForAttrEncoding() and AppendEncodedCharacters() could have experienced integer overflows, causing underallocation of an output buffer leading to an out of bounds write.

CVE-2023-5388: NSS susceptible to timing attack against RSA decryption
NSS was susceptible to a timing side-channel attack when performing RSA decryption. This attack could potentially allow an attacker to recover the private data.

CVE-2024-2609: Permission prompt input delay could expire when not in focus
The permission prompt input delay could have expired while the window is not in focus, which made the prompt vulnerable to clickjacking by malicious websites.

CVE-2024-2610: Improper handling of html and body tags enabled CSP nonce leakage
Using a markup injection an attacker could have stolen nonce values. This could have been used to bypass strict content security policies.

CVE-2024-2611: Clickjacking vulnerability could have led to a user accidentally granting permissions
A missing delay on when pointer lock was used could have allowed a malicious page to trick a user into granting permissions.

CVE-2024-2612: Self referencing object could have potentially led to a use-after-free
If an attacker could find a way to trigger a particular code path in SafeRefPtr, it could have triggered a crash or potentially be leveraged to achieve code execution.

CVE-2024-2613: Improper handling of QUIC ACK frame data could have led to OOM
Data was not properly sanitized when decoding a QUIC ACK frame, this could have led to unrestricted memory consumption and a crash.

CVE-2024-2614: Memory safety bugs fixed in Firefox 124, Firefox ESR 115.9, and Thunderbird 115.9
Memory safety bugs present in Firefox 123, Firefox ESR 115.8, and Thunderbird 115.8. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2024-2615: Memory safety bugs fixed in Firefox 124
Memory safety bugs present in Firefox 123. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 124.");

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

if (version_is_less(version: version, test_version: "124")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "124", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
