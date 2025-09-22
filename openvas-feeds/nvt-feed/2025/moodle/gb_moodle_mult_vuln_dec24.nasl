# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131502");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2025-01-02 09:19:56 +0000 (Thu, 02 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2024-55643", "CVE-2024-55644", "CVE-2024-55645", "CVE-2024-55646",
                "CVE-2024-55648");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 4.1.15, 4.3.x < 4.3.9, 4.4.x < 4.4.5, 4.5.x < 4.5.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-55643 / MSA-24-0051: Insufficient capability checks in a learning plan web service
  could result in users having the ability to retrieve information they did not have permission to
  access (such as users' names).

  - CVE-2024-55644 / MSA-24-0052: Insufficient checks meant users could see users tagged with a
  tag, regardless of whether they had access to view the users' profiles.

  - CVE-2024-55645 / MSA-24-0053: On sites requiring a confirmation step to update a user's email
  address, the token used to verify the change should only be accessible via the confirmation
  email, but was otherwise retrievable by the user.

  - CVE-2024-55646 / MSA-24-0054: In a database activity with separate groups mode enabled, users
  who were not in a group (and did not have permission to access all groups) could see entries
  from members of all groups in the activity, rather than just entries of users also not in any
  groups. Note: Users within groups worked as intended, only able to see entries belonging to other
  members of their group(s).

  - CVE-2024-55648 / MSA-24-0056: Guest user sessions were given a longer timeout than
  authenticated users, which could result in an elevated denial of service risk.");

  script_tag(name:"affected", value:"Moodle version prior to 4.1.15, 4.3.x prior to 4.3.9, 4.4.x
  prior to 4.4.5 and 4.5.x prior to 4.5.1.");

  script_tag(name:"solution", value:"Update to version 4.1.15, 4.3.9, 4.4.5, 4.5.1 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=464554");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=464555");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=464556");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=464557");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=464559");

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

if (version_is_less(version: version, test_version: "4.1.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3.0", test_version_up: "4.3.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4.0", test_version_up: "4.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.5.0", test_version_up: "4.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
