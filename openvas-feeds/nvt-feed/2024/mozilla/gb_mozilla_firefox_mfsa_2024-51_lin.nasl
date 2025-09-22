# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2024.51");
  script_cve_id("CVE-2024-9680");
  script_tag(name:"creation_date", value:"2024-10-09 13:32:45 +0000 (Wed, 09 Oct 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-16 15:07:36 +0000 (Wed, 16 Oct 2024)");

  script_name("Mozilla Firefox Security Advisory (MFSA2024-51) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2024-51");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-51/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1923344");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2024-49039");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-9680: Use-after-free in Animation timeline
An attacker was able to achieve code execution in the content process by exploiting a use-after-free in Animation timelines.
We have had reports of this vulnerability being exploited in the wild.");

  script_tag(name:"affected", value:"Firefox version(s) below 131.0.2.");

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

if (version_is_less(version: version, test_version: "131.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "131.0.2", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
