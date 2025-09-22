# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.47");
  script_cve_id("CVE-2025-49709", "CVE-2025-49710");
  script_tag(name:"creation_date", value:"2025-06-10 14:52:51 +0000 (Tue, 10 Jun 2025)");
  script_version("2025-06-11T05:40:41+0000");
  script_tag(name:"last_modification", value:"2025-06-11 05:40:41 +0000 (Wed, 11 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-47) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-47");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-47/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1966083");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1970095");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-49709: Memory corruption in canvas surfaces
Certain canvas operations could have lead to memory corruption.

CVE-2025-49710: Integer overflow in OrderedHashTable
An integer overflow was present in OrderedHashTable used by the JavaScript engine");

  script_tag(name:"affected", value:"Firefox version(s) below 139.0.4.");

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

if (version_is_less(version: version, test_version: "139.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "139.0.4", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
