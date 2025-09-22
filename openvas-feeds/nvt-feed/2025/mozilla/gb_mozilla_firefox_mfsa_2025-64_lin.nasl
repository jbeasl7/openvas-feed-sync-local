# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.64");
  script_cve_id("CVE-2025-9179", "CVE-2025-9180", "CVE-2025-9181", "CVE-2025-9182", "CVE-2025-9183", "CVE-2025-9184", "CVE-2025-9185", "CVE-2025-9187");
  script_tag(name:"creation_date", value:"2025-08-20 10:17:25 +0000 (Wed, 20 Aug 2025)");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-21 18:28:45 +0000 (Thu, 21 Aug 2025)");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-64) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-64");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-64/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1825621%2C1970079%2C1976736%2C1979072");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1929482%2C1976376%2C1979163%2C1979955");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1970154%2C1976782%2C1977166");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1975837");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1976102");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1977130");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1979527");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1979782");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-9179: Sandbox escape due to invalid pointer in the Audio/Video: GMP component
An attacker was able to perform memory corruption in the GMP process which processes encrypted media. This process is also heavily sandboxed, but represents slightly different privileges from the content process.

CVE-2025-9180: Same-origin policy bypass in the Graphics: Canvas2D component
'Same-origin policy bypass in the Graphics: Canvas2D component.'

CVE-2025-9181: Uninitialized memory in the JavaScript Engine component
Uninitialized memory in the JavaScript Engine component.

CVE-2025-9182: Denial-of-service due to out-of-memory in the Graphics: WebRender component
'Denial-of-service due to out-of-memory in the Graphics: WebRender component.'

CVE-2025-9183: Spoofing issue in the Address Bar component
Spoofing issue in the Address Bar component.

CVE-2025-9187: Memory safety bugs fixed in Firefox 142 and Thunderbird 142
Memory safety bugs present in Firefox 141 and Thunderbird 141. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2025-9184: Memory safety bugs fixed in Firefox ESR 140.2, Thunderbird ESR 140.2, Firefox 142 and Thunderbird 142
Memory safety bugs present in Firefox ESR 140.1, Thunderbird ESR 140.1, Firefox 141 and Thunderbird 141. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2025-9185: Memory safety bugs fixed in Firefox ESR 115.27, Firefox ESR 128.14, Thunderbird ESR 128.14, Firefox ESR 140.2, Thunderbird ESR 140.2, Firefox 142 and Thunderbird 142
Memory safety bugs present in Firefox ESR 115.26, Firefox ESR 128.13, Thunderbird ESR 128.13, Firefox ESR 140.1, Thunderbird ESR 140.1, Firefox 141 and Thunderbird 141. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 142.");

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

if (version_is_less(version: version, test_version: "142")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "142", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
