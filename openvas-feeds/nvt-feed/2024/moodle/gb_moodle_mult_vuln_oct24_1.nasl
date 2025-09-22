# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131089");
  script_version("2024-11-22T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-11-22 05:05:35 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-10-25 08:51:16 +0000 (Fri, 25 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-20 14:45:10 +0000 (Wed, 20 Nov 2024)");

  script_cve_id("CVE-2024-48896", "CVE-2024-48897", "CVE-2024-48898", "CVE-2024-48901");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 4.1.14, 4.2.x < 4.2.11, 4.3.x < 4.3.8, 4.4.x < 4.4.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-48896 / MMSA-24-0045: It's possible for users with the 'send message' capability to
  view other users' names they may not have access to, via an error message in Messaging.

  - CVE-2024-48897 / MMSA-24-0046: Insufficient checks to ensure users can only edit or delete RSS
  feeds they have permission to modify.

  - CVE-2024-48898 / MMSA-24-0047: Users with access to delete audiences from some reports are able
  to delete audiences from other reports they did not have permission to delete from.

  - CVE-2024-48901 / MMSA-24-0050: Insufficient checks to ensure users can only access the schedule
  of a report if they have permission to edit that report.");

  script_tag(name:"affected", value:"Moodle version prior to 4.1.14, 4.2.x prior to 4.2.11,
  4.3.x prior to 4.3.8 and 4.4.x prior to 4.4.4.");

  script_tag(name:"solution", value:"Update to version 4.1.14, 4.2.11, 4.3.8, 4.4.4 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=462874");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=462876");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=462877");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=462880");

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

if (version_is_less(version: version, test_version: "4.1.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2.0", test_version_up: "4.2.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3.0", test_version_up: "4.3.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4.0", test_version_up: "4.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

