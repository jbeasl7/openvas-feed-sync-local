# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2024.15");
  script_cve_id("CVE-2024-29943", "CVE-2024-29944");
  script_tag(name:"creation_date", value:"2024-03-22 15:00:07 +0000 (Fri, 22 Mar 2024)");
  script_version("2024-03-28T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-03-28 05:05:42 +0000 (Thu, 28 Mar 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mozilla Firefox Security Advisory (MFSA2024-15) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2024-15");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-15/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1886849");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1886852");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-29943: Out-of-bounds access via Range Analysis bypass
An attacker was able to perform an out-of-bounds read or write on a JavaScript object by fooling range-based bounds check elimination.

CVE-2024-29944: Privileged JavaScript Execution via Event Handlers
An attacker was able to inject an event handler into a privileged object that would allow arbitrary JavaScript execution in the parent process. Note: This vulnerability affects Desktop Firefox only, it does not affect mobile versions of Firefox.");

  script_tag(name:"affected", value:"Firefox version(s) below 124.0.1.");

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

if (version_is_less(version: version, test_version: "124.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "124.0.1", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
