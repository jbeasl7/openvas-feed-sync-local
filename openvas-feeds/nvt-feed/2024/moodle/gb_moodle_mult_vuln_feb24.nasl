# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126597");
  script_version("2025-01-24T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-24 05:37:33 +0000 (Fri, 24 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-02-20 08:50:42 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-23 16:42:27 +0000 (Thu, 23 Jan 2025)");

  script_cve_id("CVE-2024-25978", "CVE-2024-25979", "CVE-2024-25980", "CVE-2024-25981",
                "CVE-2024-25982", "CVE-2024-25983");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle 4.1.x < 4.1.9, 4.2.x < 4.2.5, 4.3.x < 4.3.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-25978: Insufficient file size checks resulted in a denial of service risk in the file
  picker's unzip functionality.

  - CVE-2024-25979: The URL parameters accepted by forum search were not limited to the allowed
  parameters.

  - CVE-2024-25980: Separate Groups mode restrictions were not honoured in the H5P attempts report,
  which would display users from other groups. By default this only provided additional access to
  non-editing teachers.

  - CVE-2024-25981: Separate Groups mode restrictions were not honoured when performing a forum
  export, which would export forum data for all groups. By default this only provided additional
  access to non-editing teachers.

  - CVE-2024-25982: The link to update all installed language packs did not include the necessary
  token to prevent a CSRF risk.

  - CVE-2024-25983: Insufficient checks in a web service made it possible to add comments to the
  comments block on another user's dashboard when it was not otherwise available (eg on their
  profile page).");

  script_tag(name:"affected", value:"Moodle versions prior to 4.1.9, 4.2.x prior to 4.2.5 and 4.3.x
  prior to 4.3.3.");

  script_tag(name:"solution", value:"Update to version 4.1.9, 4.2.5, 4.3.3 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=455634");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=455635");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=455636");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=455637");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=455638");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=455641");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.1.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2", test_version_up: "4.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3", test_version_up: "4.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
