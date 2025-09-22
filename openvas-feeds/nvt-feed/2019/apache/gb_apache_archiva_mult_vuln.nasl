# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:archiva";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142374");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-05-06 13:02:47 +0000 (Mon, 06 May 2019)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-0213", "CVE-2019-0214");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Archiva < 2.2.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_archiva_http_detect.nasl");
  script_mandatory_keys("apache/archiva/detected");

  script_tag(name:"summary", value:"Apache Archiva is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2019-0213: Cross-site scripting (XSS) vulnerability

  - CVE-2019-0214: Arbitrary file write and delete vulnerability");

  script_tag(name:"affected", value:"Apache Archiva prior to version 2.2.4.");

  script_tag(name:"solution", value:"Update to version 2.2.4 or later.");

  script_xref(name:"URL", value:"https://archiva.apache.org/security.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "2.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.4", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
