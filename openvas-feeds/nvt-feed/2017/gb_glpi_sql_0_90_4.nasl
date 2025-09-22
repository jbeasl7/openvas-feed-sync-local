# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:glpi-project:glpi";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107227");
  script_version("2025-04-04T15:42:05+0000");
  script_tag(name:"last_modification", value:"2025-04-04 15:42:05 +0000 (Fri, 04 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-06-28 14:43:29 +0200 (Wed, 28 Jun 2017)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GLPI 0.90.4 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_glpi_http_detect.nasl");
  script_mandatory_keys("glpi/detected");

  script_tag(name:"summary", value:"GLPI is prone to an SQL injection (SQLi) vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The attack is due to the variable dbenc which when configured
  by the admin to big5, it allows SQL injection in almost all the forms of the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow an authenticated remote
  attacker to execute arbitrary SQL commands by using the [ELIDED] character when the database is
  configured to use asian encoding (BIG 5).");

  script_tag(name:"affected", value:"GLPI version 0.90.4.");

  script_tag(name:"solution", value:"Update to version 9.1 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42262/");

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

if (version_is_equal(version: version, test_version: "0.90.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
