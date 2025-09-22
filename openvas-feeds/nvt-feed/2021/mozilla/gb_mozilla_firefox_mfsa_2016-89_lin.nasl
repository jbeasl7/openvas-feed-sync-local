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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2016.89");
  script_cve_id("CVE-2016-5289", "CVE-2016-5290", "CVE-2016-5291", "CVE-2016-5292", "CVE-2016-5296", "CVE-2016-5297", "CVE-2016-9063", "CVE-2016-9064", "CVE-2016-9066", "CVE-2016-9067", "CVE-2016-9068", "CVE-2016-9069", "CVE-2016-9070", "CVE-2016-9071", "CVE-2016-9073", "CVE-2016-9074", "CVE-2016-9075", "CVE-2016-9076", "CVE-2016-9077");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2022-09-22T10:44:54+0000");
  script_tag(name:"last_modification", value:"2022-09-22 10:44:54 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-30 10:34:00 +0000 (Mon, 30 Jul 2018)");

  script_name("Mozilla Firefox Security Advisory (MFSA2016-89) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2016-89");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-89/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1296649%2C1298107%2C1300129%2C1305876%2C1314667%2C1301252%2C1277866%2C1307254%2C1252511%2C1264053");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1309720%2C1297062%2C1303710%2C1018486%2C1292590%2C1301343%2C1301496%2C1308048%2C1308346%2C1299519%2C1286911%2C1298169");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1274777");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1276976");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1281071");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1285003");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1288482");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1289273");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1292159");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1292443");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1293334");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1295324");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1298552");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1299686");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1301777");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1302973");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1303418");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1303678");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1308922");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2016-5296: Heap-buffer-overflow WRITE in rasterize_edges_1
A heap-buffer-overflow in Cairo when processing SVG content caused by compiler optimization, resulting in a potentially exploitable crash.

CVE-2016-5292: URL parsing causes crash
During URL parsing, a maliciously crafted URL can cause a potentially exploitable crash.

CVE-2016-5297: Incorrect argument length checking in JavaScript
An error in argument length checking in JavaScript, leading to potential integer overflows or other bounds checking issues.

CVE-2016-9064: Add-ons update must verify IDs match between current and new versions
Add-on updates failed to verify that the add-on ID inside the signed package matched the ID of the add-on being updated. An attacker who could perform a man-in-the-middle attack on the user's connection to the update server and defeat the certificate pinning protection could provide a malicious signed add-on instead of a valid update.

CVE-2016-9066: Integer overflow leading to a buffer overflow in nsScriptLoadHandler
A buffer overflow resulting in a potentially exploitable crash due to memory allocation issues when handling large amounts of incoming data.

CVE-2016-9067: heap-use-after-free in nsINode::ReplaceOrInsertBefore
Two use-after-free errors during DOM operations resulting in potentially exploitable crashes.

CVE-2016-9068: heap-use-after-free in nsRefreshDriver
A use-after-free during web animations when working with timelines resulting in a potentially exploitable crash.

CVE-2016-9075: WebExtensions can access the mozAddonManager ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 50.");

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

if (version_is_less(version: version, test_version: "50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "50", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
