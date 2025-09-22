# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126747");
  script_version("2024-07-19T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-05-14 10:53:02 +0000 (Tue, 14 May 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-18 16:41:31 +0000 (Thu, 18 Jul 2024)");

  script_cve_id("CVE-2024-33996", "CVE-2024-33997", "CVE-2024-33998", "CVE-2024-34000",
                "CVE-2024-34001", "CVE-2024-34002", "CVE-2024-34003", "CVE-2024-34004",
                "CVE-2024-34005", "CVE-2024-34006", "CVE-2024-34008");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 4.1.10, 4.2.x < 4.2.7, 4.3.x < 4.3.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - MSA-24-0007 / CVE-2024-33996: Incorrect validation of allowed event types in a calendar web
  service made it possible for some users to create events with types/audiences they did not have
  permission to publish to.

  - MSA-24-0008 / CVE-2024-33997: Additional sanitizing was required when opening the equation
  editor, to prevent a stored XSS risk when editing another user's equation.

  - MSA-24-0009 / CVE-2024-33998: Insufficient escaping of participants' names in the participants
  page table resulted in a stored XSS risk when interacting with some features.

  - MSA-24-0011: CVE-2024-34000: ID numbers displayed in the lesson overview report required
  additional sanitizing to prevent a stored XSS risk.

  - MSA-24-0012: CVE-2024-34001: Actions in the admin preset tool did not include the necessary
  token to prevent a CSRF risk.

  - MSA-24-0013 / CVE-2024-34002: In a shared hosting environment that has been misconfigured to
  allow access to other users' content, a Moodle user with both access to restore feedback modules
  and direct access to the web server outside of the Moodle webroot could execute a local file
  include.

  - MSA-24-0014 / CVE-2024-34003: In a shared hosting environment that has been misconfigured to
  allow access to other users' content, a Moodle user with both access to restore workshop modules
  and direct access to the web server outside of the Moodle webroot could execute a local file
  include.

  - MSA-24-0015 / CVE-2024-34004: In a shared hosting environment that has been misconfigured to
  allow access to other users' content, a Moodle user with both access to restore wiki modules and
  direct access to the web server outside of the Moodle webroot could execute a local file include.

  - MSA-24-0016 / CVE-2024-34005: In a shared hosting environment that has been misconfigured to
  allow access to other users' content, a Moodle user with both access to restore database activity
  modules and direct access to the web server outside of the Moodle webroot could execute a local
  file include.

  - MSA-24-0017 / CVE-2024-34006: The site log report required additional encoding of event
  descriptions to ensure any HTML in the content is displayed in plaintext instead of being
  rendered.

  - MSA-24-0019 / CVE-2024-34008: Actions in the admin management of analytics models did not
  include the necessary token to prevent a CSRF risk.");

  script_tag(name:"affected", value:"Moodle version prior to 4.1.10, 4.2.x prior to 4.2.7 and
  4.3.x prior to 4.3.4.");

  script_tag(name:"solution", value:"Update to version 4.1.10, 4.2.7, 4.3.4 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=458384");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=458385");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=458386");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=458388");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=458389");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=458390");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=458391");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=458393");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=458394");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=458395");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=458397");

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

if (version_is_less(version: version, test_version: "4.1.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2", test_version_up: "4.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3", test_version_up: "4.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
