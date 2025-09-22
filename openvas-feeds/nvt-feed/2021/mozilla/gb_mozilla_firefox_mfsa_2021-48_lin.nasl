# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2021.48");
  script_cve_id("CVE-2021-38503", "CVE-2021-38504", "CVE-2021-38506", "CVE-2021-38507", "CVE-2021-38508", "CVE-2021-38509");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2022-09-22T10:44:54+0000");
  script_tag(name:"last_modification", value:"2022-09-22 10:44:54 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-13 19:53:00 +0000 (Mon, 13 Dec 2021)");

  script_name("Mozilla Firefox Security Advisory (MFSA2021-48) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2021-48");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-48/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1606864%2C1712671%2C1730048%2C1735152");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1366818");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1659155");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1718571");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1719203");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1724233");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1729517");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1730156");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1730750");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1730935");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-38503: iframe sandbox rules did not apply to XSLT stylesheets
The iframe sandbox rules were not correctly applied to XSLT stylesheets, allowing an iframe to bypass restrictions such as executing scripts or navigating the top-level frame.

CVE-2021-38504: Use-after-free in file picker dialog
When interacting with an HTML input element's file picker dialog with webkitdirectory set, a use-after-free could have resulted, leading to memory corruption and a potentially exploitable crash.

CVE-2021-38506: Firefox could be coaxed into going into fullscreen mode without notification or warning
Through a series of navigations, Firefox could have entered fullscreen mode without notification or warning to the user. This could lead to spoofing attacks on the browser UI including phishing.

CVE-2021-38507: Opportunistic Encryption in HTTP2 could be used to bypass the Same-Origin-Policy on services hosted on other ports
The Opportunistic Encryption feature of HTTP2 (RFC 8164) allows a connection to be transparently upgraded to TLS while retaining the visual properties of an HTTP connection, including being same-origin with unencrypted connections on port 80. However, if a second encrypted port on the same IP address (e.g. port 8443) did not opt-in to opportunistic encryption, a network attacker could forward a connection from the browser to port 443 to port 8443, causing the browser to treat the content of port 8443 as same-origin with HTTP. This was resolved by disabling the Opportunistic Encryption feature, which had low usage.

CVE-2021-38508: Permission Prompt could be overlaid, resulting in user confusion and potential spoofing
By displaying a form validity message in the correct location at the same time as a permission prompt (such as for geolocation), the validity message could have obscured the prompt, resulting in the user ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 94.");

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

if (version_is_less(version: version, test_version: "94")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "94", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
