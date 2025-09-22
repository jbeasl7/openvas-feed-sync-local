# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:wicket";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811841");
  script_version("2025-04-01T05:39:41+0000");
  script_tag(name:"last_modification", value:"2025-04-01 05:39:41 +0000 (Tue, 01 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-10-04 13:06:12 +0530 (Wed, 04 Oct 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-24 18:19:00 +0000 (Tue, 24 Mar 2020)");

  script_cve_id("CVE-2014-7808");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Wicket 'CryptoMapper' CSRF Vulnerability (Feb 2015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_wicket_consolidation.nasl");
  script_mandatory_keys("apache/wicket/detected");

  script_tag(name:"summary", value:"Apache Wicket is prone to a cross-site request forgery (CSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to Wicket's default security settings of the
  usage of CryptoMapper to encrypt/obfuscate pages urls, which is not strong enough. It is possible
  to predict the encrypted version of an url based on the previous history.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to defeat a
  cryptographic protection mechanism and predict encrypted URLs by leveraging use of CryptoMapper as
  the default encryption provider.");

  script_tag(name:"affected", value:"Apache Wicket versions before 1.5.13, 6.x before 6.19.0 and
  7.x before 7.0.0-M5.");

  script_tag(name:"solution", value:"Update to version 1.5.13, 6.19.0, 7.0.0-M5 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/rqy6lpo5mzco85cbf65r53vdh87gz77b");
  script_xref(name:"URL", value:"https://www.smrrd.de/cve-2014-7808-apache-wicket-csrf-2014.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210124104412/http://www.securityfocus.com/bid/100946");

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

if (version_is_less(version: version, test_version: "1.5.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.19.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.19.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0-M1", test_version_up: "7.0.0-M5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0-M5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
