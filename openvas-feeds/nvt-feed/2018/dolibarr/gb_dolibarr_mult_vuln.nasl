# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dolibarr:dolibarr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112216");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-02-12 10:00:40 +0100 (Mon, 12 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-09 16:11:00 +0000 (Tue, 09 Jan 2018)");

  script_cve_id("CVE-2017-17900", "CVE-2017-17898", "CVE-2017-17899", "CVE-2017-17897");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dolibarr < 6.0.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_http_detect.nasl");
  script_mandatory_keys("dolibarr/detected");

  script_tag(name:"summary", value:"Dolibarr is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2017-17900: SQL injection in fourn/index.php allows remote attackers to execute arbitrary
  SQL commands via the socid parameter.

  - CVE-2017-17898: Dolibarr does not block direct requests to *.tpl.php files, which allows remote
  attackers to obtain sensitive information.

  - CVE-2017-17899: SQL injection in adherents/subscription/info.php allows remote attackers to
  execute arbitrary SQL commands via the rowid parameter.

  - CVE-2017-17897: SQL injection in comm/multiprix.php allows remote attackers to execute
  arbitrary SQL commands via the id parameter.");

  script_tag(name:"affected", value:"Dolibarr version 6.0.4 and prior.");

  script_tag(name:"solution", value:"Update to version 6.0.5 or later.");

  script_xref(name:"URL", value:"https://github.com/Dolibarr/dolibarr/blob/develop/ChangeLog");

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

if (version_is_less(version: version, test_version: "6.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
