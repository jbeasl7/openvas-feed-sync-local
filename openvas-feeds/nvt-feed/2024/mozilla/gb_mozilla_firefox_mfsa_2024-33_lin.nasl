# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2024.33");
  script_cve_id("CVE-2024-7518", "CVE-2024-7519", "CVE-2024-7520", "CVE-2024-7521", "CVE-2024-7522", "CVE-2024-7524", "CVE-2024-7525", "CVE-2024-7526", "CVE-2024-7527", "CVE-2024-7528", "CVE-2024-7529", "CVE-2024-7530", "CVE-2024-7531", "CVE-2024-8900");
  script_tag(name:"creation_date", value:"2024-08-06 14:50:23 +0000 (Tue, 06 Aug 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-12 16:04:20 +0000 (Mon, 12 Aug 2024)");

  script_name("Mozilla Firefox Security Advisory (MFSA2024-33) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2024-33");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-33/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1871303");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1872841");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1875354");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1895951");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1902307");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1903041");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1903187");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1904011");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1904644");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1905691");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1906727");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1909241");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1909298");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1910306");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-7518: Fullscreen notification dialog can be obscured by document content
Select options could obscure the fullscreen notification dialog. This could be used by a malicious site to perform a spoofing attack.

CVE-2024-7519: Out of bounds memory access in graphics shared memory handling
Insufficient checks when processing graphics shared memory could have led to memory corruption. This could be leveraged by an attacker to perform a sandbox escape.

CVE-2024-7520: Type confusion in WebAssembly
A type confusion bug in WebAssembly could be leveraged by an attacker to potentially achieve code execution.

CVE-2024-7521: Incomplete WebAssembly exception handing
Incomplete WebAssembly exception handing could have led to a use-after-free.

CVE-2024-7522: Out of bounds read in editor component
Editor code failed to check an attribute value. This could have led to an out-of-bounds read.

CVE-2024-7524: CSP strict-dynamic bypass using web-compatibility shims
Firefox adds web-compatibility shims in place of some tracking scripts blocked by Enhanced Tracking Protection. On a site protected by Content Security Policy in 'strict-dynamic' mode, an attacker able to inject an HTML element could have used a DOM Clobbering attack on some of the shims and achieved XSS, bypassing the CSP strict-dynamic protection.

CVE-2024-7525: Missing permission check when creating a StreamFilter
It was possible for a web extension with minimal permissions to create a StreamFilter which could be used to read and modify the response body of requests on any site.

CVE-2024-7526: Uninitialized memory used by WebGL
ANGLE failed to initialize parameters which lead to reading from uninitialized memory. This could be leveraged to leak sensitive data from memory.

CVE-2024-7527: Use-after-free in JavaScript garbage collection
Unexpected marking work at the start of sweeping could have led to a use-after-free.

CVE-2024-7528: Use-after-free in IndexedDB
Incorrect garbage collection interaction in IndexedDB could have led to a use-after-free.

CVE-2024-8900: Clipboard write permission bypass
An attacker could write data to the user's clipboard, bypassing the user prompt, during a certain sequence of navigational events.

CVE-2024-7529: Document content could partially obscure security prompts
The date picker could partially obscure security prompts. This could be used by a malicious site to trick a user into granting permissions.

CVE-2024-7530: Use-after-free in JavaScript code coverage collection
Incorrect garbage collection interaction could have led to a use-after-free.

CVE-2024-7531: PK11_Encrypt using CKM_CHACHA20 can reveal plaintext on ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 129.");

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

if (version_is_less(version: version, test_version: "129")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "129", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
