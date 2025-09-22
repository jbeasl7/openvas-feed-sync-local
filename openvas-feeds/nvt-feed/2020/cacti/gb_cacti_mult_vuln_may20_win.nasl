# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cacti:cacti";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143962");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-05-25 08:37:15 +0000 (Mon, 25 May 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-05 05:15:00 +0000 (Fri, 05 Jun 2020)");

  script_cve_id("CVE-2020-13230", "CVE-2020-13231");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cacti < 1.2.11 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cacti_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Cacti is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cacti is prone to multiple vulnerabilities:

  - Disabling a user account does not immediately invalidate any permissions granted to that account
    (e.g., permission to view logs) (CVE-2020-13230)

  - auth_profile.php?action=edit allows CSRF for an admin email change (CVE-2020-13231)");

  script_tag(name:"affected", value:"Cacti prior to version 1.2.11.");

  script_tag(name:"solution", value:"Update to version 1.2.11 or later.");

  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/3343");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/3342");

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

if (version_is_less(version: version, test_version: "1.2.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.11", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
