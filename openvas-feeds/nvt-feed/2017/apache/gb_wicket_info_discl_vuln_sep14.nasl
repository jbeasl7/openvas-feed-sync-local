# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:wicket";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812103");
  script_version("2025-04-01T05:39:41+0000");
  script_tag(name:"last_modification", value:"2025-04-01 05:39:41 +0000 (Tue, 01 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-11-10 16:11:14 +0530 (Fri, 10 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-11 22:12:00 +0000 (Wed, 11 Dec 2019)");

  script_cve_id("CVE-2014-3526");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Wicket Information Disclosure Vulnerability (Sep 2014)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_wicket_consolidation.nasl");
  script_mandatory_keys("apache/wicket/detected");

  script_tag(name:"summary", value:"Apache Wicket is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When storing the page markup at the server side Wicket uses as
  an identifier a pair of the current session id plus the new url. However, Wicket does not check if
  user session is temporary.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Apache Wicket versions prior to 1.5.12, 6.x prior to 6.17.0
  and 7.x prior to 7.0.0-M3.");

  script_tag(name:"solution", value:"Update to version 1.5.12, 6.17.0, 7.0.0-M3 or later.");

  script_xref(name:"URL", value:"https://wicket.apache.org/news/2014/09/22/cve-2014-3526.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.5.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.17.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.17.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0-M1", test_version_up: "7.0.0-M3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0-M3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
