# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2022.40");
  script_cve_id("CVE-2022-3266", "CVE-2022-40956", "CVE-2022-40957", "CVE-2022-40958", "CVE-2022-40959", "CVE-2022-40960", "CVE-2022-40962", "CVE-2022-46880");
  script_tag(name:"creation_date", value:"2022-09-21 05:31:55 +0000 (Wed, 21 Sep 2022)");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 02:59:00 +0000 (Wed, 04 Jan 2023)");

  script_name("Mozilla Firefox Security Advisory (MFSA2022-40) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2022-40");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-40/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1776655%2C1777574%2C1784835%2C1785109%2C1786502%2C1789440");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1749292");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1767360");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1770094");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1777604");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1779993");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1782211");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1787633");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-3266: Out of bounds read when decoding H264
An out-of-bounds read can occur when decoding H264 video. This results in a potentially exploitable crash.

CVE-2022-40959: Bypassing FeaturePolicy restrictions on transient pages
During iframe navigation, certain pages did not have their FeaturePolicy fully initialized leading to a bypass that leaked device permissions into untrusted subdocuments.

CVE-2022-40960: Data-race when parsing non-UTF-8 URLs in threads
Concurrent use of the URL parser with non-UTF-8 data was not thread-safe. This could lead to a use-after-free causing a potentially exploitable crash.

CVE-2022-46880: Use-after-free in WebGL
A missing check related to tex units could have led to a use-after-free and potentially exploitable crash.Note: This advisory was added on December 13th, 2022 after we better understood the impact of the issue. The fix was included in the original release of Firefox 105.

CVE-2022-40958: Bypassing Secure Context restriction for cookies with __Host and __Secure prefix
By injecting a cookie with certain special characters, an attacker on a shared subdomain which is not a secure context could set and thus overwrite cookies from a secure context, leading to session fixation and other attacks.

CVE-2022-40956: Content-Security-Policy base-uri bypass
When injecting an HTML base element, some requests would ignore the CSP's base-uri settings and accept the injected element's base instead.

CVE-2022-40957: Incoherent instruction cache when building WASM on ARM64
Inconsistent data in instruction and data cache when creating wasm code could lead to a potentially exploitable crash.This bug only affects Firefox on ARM64 platforms.

CVE-2022-40962: Memory safety bugs fixed in Firefox 105 and Firefox ESR 102.3
Mozilla developers Nika Layzell, Timothy Nikkel, Sebastian Hengst, Andreas Pehrson, and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 104 and Firefox ESR 102.2. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 105.");

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

if (version_is_less(version: version, test_version: "105")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "105", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
