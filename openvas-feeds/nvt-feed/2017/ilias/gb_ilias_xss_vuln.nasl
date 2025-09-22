# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ilias:ilias";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140444");
  script_version("2023-11-15T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-11-15 05:05:25 +0000 (Wed, 15 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-10-20 12:39:08 +0700 (Fri, 20 Oct 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-19 14:59:00 +0000 (Tue, 19 Jun 2018)");

  script_cve_id("CVE-2017-15538");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS < 5.1.21, 5.2.x < 5.2.9 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ilias_http_detect.nasl");
  script_mandatory_keys("ilias/detected");

  script_tag(name:"summary", value:"ILIAS eLearning is prone to a stored cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Stored XSS vulnerability in the Media Objects component of ILIAS
  allows an authenticated user to inject JavaScript to gain administrator privileges, related to the
  setParameter function in Services/MediaObjects/classes/class.ilMediaItem.php.");

  script_tag(name:"affected", value:"ILIAS prior to version 5.1.21 and 5.2.x prior to 5.2.9.");

  script_tag(name:"solution", value:"Update to version 5.1.21, 5.2.9 or later.");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/10/17/3");
  script_xref(name:"URL", value:"https://www.ilias.de/docu/goto_docu_pg_75377_35.html");
  script_xref(name:"URL", value:"https://www.ilias.de/docu/goto_docu_pg_75378_1719.html");

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

if (version_is_less(version: version, test_version: "5.1.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^5\.2\.") {
  if (version_is_less(version: version, test_version: "5.2.9")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.2.9", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
