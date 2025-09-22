# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.51");
  script_cve_id("CVE-2025-6424", "CVE-2025-6425", "CVE-2025-6427", "CVE-2025-6429", "CVE-2025-6430", "CVE-2025-6432", "CVE-2025-6433", "CVE-2025-6434", "CVE-2025-6435", "CVE-2025-6436");
  script_tag(name:"creation_date", value:"2025-06-24 16:15:26 +0000 (Tue, 24 Jun 2025)");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-51) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-51");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-51/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1941377%2C1960948%2C1966187%2C1966505%2C1970764");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1717672");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1943804");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1950056");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1954033");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1955182");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1961777");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1966423");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1966927");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1970658");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1971140");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-6424: Use-after-free in FontFaceSet
A use-after-free in FontFaceSet resulted in a potentially exploitable crash.

CVE-2025-6425: The WebCompat WebExtension shipped with Firefox exposed a persistent UUID
An attacker who enumerated resources from the WebCompat extension could have obtained a persistent UUID that identified the browser, and persisted between containers and normal/private browsing mode, but not profiles.

CVE-2025-6427: connect-src Content Security Policy restriction could be bypassed
An attacker was able to bypass the connect-src directive of a Content Security Policy by manipulating subdocuments. This would have also hidden the connections from the Network tab in Devtools.

CVE-2025-6429: Incorrect parsing of URLs could have allowed embedding of youtube.com
Firefox could have incorrectly parsed a URL and rewritten it to the youtube.com domain when parsing the URL specified in an embed tag. This could have bypassed website security checks that restricted which domains users were allowed to embed.

CVE-2025-6430: Content-Disposition header ignored when a file is included in an embed or object tag
When a file download is specified via the Content-Disposition header, that directive would be ignored if the file was included via a <embed> or <object> tag, potentially making a website vulnerable to a cross-site scripting attack.

CVE-2025-6432: DNS Requests leaked outside of a configured SOCKS proxy
When Multi-Account Containers was enabled, DNS requests could have bypassed a SOCKS proxy when the domain name was invalid or the SOCKS proxy was not responding.

CVE-2025-6433: WebAuthn would allow a user to sign a challenge on a webpage with an invalid TLS certificate
If a user visited a webpage with an invalid TLS certificate, and granted an exception, the webpage was able to provide a WebAuthn ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 140.");

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

if (version_is_less(version: version, test_version: "140")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "140", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
