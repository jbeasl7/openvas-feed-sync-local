# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.73");
  script_cve_id("CVE-2025-10527", "CVE-2025-10528", "CVE-2025-10529", "CVE-2025-10531", "CVE-2025-10532", "CVE-2025-10533", "CVE-2025-10534", "CVE-2025-10536", "CVE-2025-10537");
  script_tag(name:"creation_date", value:"2025-09-17 12:48:05 +0000 (Wed, 17 Sep 2025)");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-73) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-73");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-73/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1938220%2C1980730%2C1981280%2C1981283%2C1984505%2C1985067");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1665334");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1970490");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1978453");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1979502");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1980788");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1981502");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1984825");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1986185");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-10527: Sandbox escape due to use-after-free in the Graphics: Canvas2D component

CVE-2025-10528: Sandbox escape due to undefined behavior, invalid pointer in the Graphics: Canvas2D component

CVE-2025-10529: Same-origin policy bypass in the Layout component

CVE-2025-10531: Mitigation bypass in the Web Compatibility: Tooling component

CVE-2025-10532: Incorrect boundary conditions in the JavaScript: GC component

CVE-2025-10533: Integer overflow in the SVG component

CVE-2025-10534: Spoofing issue in the Site Permissions component

CVE-2025-10536: Information disclosure in the Networking: Cache component

CVE-2025-10537: Memory safety bugs fixed in Firefox ESR 140.3, Thunderbird ESR 140.3, Firefox 143 and Thunderbird 143

Memory safety bugs present in Firefox ESR 140.2, Thunderbird ESR 140.2, Firefox 142 and Thunderbird 142. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 143.");

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

if (version_is_less(version: version, test_version: "143")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "143", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
