# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156686");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"creation_date", value:"2026-04-02 02:29:35 +0000 (Thu, 02 Apr 2026)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2026-21630", "CVE-2026-21631", "CVE-2026-21632", "CVE-2026-23898",
                "CVE-2026-23899");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! Multiple Vulnerabilities (20260302, 20260303, 20260304, 20260305, 20260306)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2026-21630: SQL injection (SQLi) in com_content articles webservice endpoint

  - CVE-2026-21631: XSS vector in com_associations comparison view

  - CVE-2026-21632: XSS vectors in various article title outputs

  - CVE-2026-23898: Arbitrary file deletion in com_joomlaupdate

  - CVE-2026-23899: Improper access check in webservice endpoints");

  script_tag(name:"affected", value:"Joomla! version 4.0.0 through 5.4.3 and 6.0.0 through
  6.0.3.");

  script_tag(name:"solution", value:"Update to version 5.4.4, 6.0.4 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/1028-20260302-core-sql-injection-in-com-content-articles-webservice-endpoint.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/1029-20260303-core-xss-vector-in-com-associations-comparison-view.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/1030-20260304-core-xss-vectors-in-various-article-title-outputs.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/1031-20260305-core-arbitrary-file-deletion-in-com-joomlaupdate.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/1032-20260306-core-improper-access-check-in-webservice-endpoints.html");

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

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "5.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
