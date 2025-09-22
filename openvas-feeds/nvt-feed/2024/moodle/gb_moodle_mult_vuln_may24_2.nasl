# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126745");
  script_version("2024-06-05T05:05:26+0000");
  script_tag(name:"last_modification", value:"2024-06-05 05:05:26 +0000 (Wed, 05 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-05-14 10:00:02 +0000 (Tue, 14 May 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2024-33999", "CVE-2024-34007", "CVE-2024-34009");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle 4.3.x < 4.3.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - MSA-24-0010 / CVE-2024-33999: The referrer URL used by MFA required additional sanitizing,
  rather than being used directly.

  - MSA-24-0018 / CVE-2024-34007: The logout option within MFA did not include the necessary token
  to avoid the risk of users inadvertently being logged out via CSRF.

  - MSA-24-0020 / CVE-2024-34009: Insufficient checks whether ReCAPTCHA was enabled made it possible
  to bypass the checks on the login page. This did not affect other pages where ReCAPTCHA is
  utilised.");

  script_tag(name:"affected", value:"Moodle version 4.3.x prior to 4.3.4.");

  script_tag(name:"solution", value:"Update to version 4.3.4 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=458387");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=458396");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=458398");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.3", test_version_up: "4.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
