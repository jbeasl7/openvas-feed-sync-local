# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.36");
  script_cve_id("CVE-2025-4918", "CVE-2025-4919");
  script_tag(name:"creation_date", value:"2025-05-19 07:37:02 +0000 (Mon, 19 May 2025)");
  script_version("2025-05-22T05:40:21+0000");
  script_tag(name:"last_modification", value:"2025-05-22 05:40:21 +0000 (Thu, 22 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-36) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-36");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-36/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1966612");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1966614");
  script_xref(name:"URL", value:"https://blog.mozilla.org/security/2025/05/17/firefox-security-response-to-pwn2own-2025/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/blog/2025/5/16/pwn2own-berlin-2025-day-two-results");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/blog/2025/5/17/pwn2own-berlin-2025-day-three-results");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-4918: Out-of-bounds access when resolving Promise objects
An attacker was able to perform an out-of-bounds read or write on a JavaScript Promise object.

CVE-2025-4919: Out-of-bounds access when optimizing linear sums
An attacker was able to perform an out-of-bounds read or write on a JavaScript object by confusing array index sizes.");

  script_tag(name:"affected", value:"Firefox version(s) below 138.0.4.");

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

if (version_is_less(version: version, test_version: "138.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "138.0.4", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
