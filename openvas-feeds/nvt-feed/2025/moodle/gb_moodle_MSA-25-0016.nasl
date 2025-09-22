# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127867");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-24 10:20:20 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2025-3628");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle Information Disclosure Vulnerability (MSA-25-0016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Teachers are able to identify a user's anonymous assignment
  submissions via the submissions search.");

  script_tag(name:"affected", value:"Moodle version 4.5 through 4.5.3.");

  script_tag(name:"solution", value:"Update to version 4.5.4 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=467595");

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

if (version_in_range(version: version, test_version: "4.5.0", test_version2: "4.5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
