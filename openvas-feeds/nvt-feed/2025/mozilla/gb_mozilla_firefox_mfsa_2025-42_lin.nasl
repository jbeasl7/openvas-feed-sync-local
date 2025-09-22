# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.42");
  script_cve_id("CVE-2025-5263", "CVE-2025-5264", "CVE-2025-5266", "CVE-2025-5267", "CVE-2025-5268", "CVE-2025-5270", "CVE-2025-5271", "CVE-2025-5272", "CVE-2025-5283");
  script_tag(name:"creation_date", value:"2025-05-27 15:41:03 +0000 (Tue, 27 May 2025)");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-42) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-42");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-42/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1726254%2C1742738%2C1960121");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1950136%2C1958121%2C1960499%2C1962634");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1910298");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1920348");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1950001");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1954137");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1960745");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1962421");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1965628");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-5283: Double-free in libvpx encoder
A double-free could have occurred in vpx_codec_enc_init_multi after a failed allocation when initializing the encoder for WebRTC. This could have caused memory corruption and a potentially exploitable crash.

CVE-2025-5263: Error handling for script execution was incorrectly isolated from web content
Error handling for script execution was incorrectly isolated from web content, which could have allowed cross-origin leak attacks.

CVE-2025-5264: Potential local code execution in 'Copy as cURL' command
Due to insufficient escaping of the newline character in the 'Copy as cURL' feature, an attacker could trick a user into using this command, potentially leading to local code execution on the user's system.

CVE-2025-5266: Script element events leaked cross-origin resource status
Script elements loading cross-origin resources generated load and error events which leaked information enabling XS-Leaks attacks.

CVE-2025-5270: SNI was sometimes unencrypted
In certain cases, SNI could have been sent unencrypted even when encrypted DNS was enabled.

CVE-2025-5271: Devtools' preview ignored CSP headers
Previewing a response in Devtools ignored CSP headers, which could have allowed content injection attacks.

CVE-2025-5267: Clickjacking vulnerability could have led to leaking saved payment card details
A clickjacking vulnerability could have been used to trick a user into leaking saved payment card details to a malicious page.

CVE-2025-5268: Memory safety bugs fixed in Firefox 139, Thunderbird 139, Firefox ESR 128.11, and Thunderbird 128.11
Memory safety bugs present in Firefox 138, Thunderbird 138, Firefox ESR 128.10, and Thunderbird 128.10. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2025-5272: Memory safety bugs fixed in Firefox 139 and Thunderbird 139
Memory safety bugs present in Firefox 138 and Thunderbird 138. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 139.");

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

if (version_is_less(version: version, test_version: "139")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "139", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
