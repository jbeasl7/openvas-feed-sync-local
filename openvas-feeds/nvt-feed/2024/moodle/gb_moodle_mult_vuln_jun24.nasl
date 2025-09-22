# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126941");
  script_version("2024-08-09T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-06-19 10:53:02 +0000 (Wed, 19 Jun 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-08 15:55:51 +0000 (Thu, 08 Aug 2024)");

  script_cve_id("CVE-2024-38273", "CVE-2024-38274", "CVE-2024-38275", "CVE-2024-38276",
                "CVE-2024-38277");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 4.1.11, 4.2.x < 4.2.8, 4.3.x < 4.3.5, 4.4.x < 4.4.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-38273 / MSA-24-0021: BigBlueButton web service leaks meeting joining information to
  users who should not have access

  - CVE-2024-38274 / MSA-24-0022: Insufficient escaping of calendar event titles results in a
  stored XSS risk in the event deletion prompt.

  - CVE-2024-38275 / MSA-24-0023: The cURL wrapper in Moodle retained the original request headers
  when following redirects, so HTTP authorization header information could be unintentionally sent
  in requests to redirect URLs.

  - CVE-2024-38276 / MSA-24-0024: CSRF risks due to misuse of confirm_sesskey

  - CVE-2024-38277 / MSA-24-0025: QR login key and auto-login key for the Moodle mobile app are
  not generated as separate keys.");

  script_tag(name:"affected", value:"Moodle version prior to 4.1.11, 4.2.x prior to 4.2.8,
  4.3.x prior to 4.3.5 and 4.4.x prior to 4.4.1.");

  script_tag(name:"solution", value:"Update to version 4.1.11, 4.2.8, 4.3.5, 4.4.1 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=459498");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=459499");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=459500");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=459501");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=459502");

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

if (version_is_less(version: version, test_version: "4.1.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2.0", test_version_up: "4.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3.0", test_version_up: "4.3.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4.0", test_version_up: "4.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
