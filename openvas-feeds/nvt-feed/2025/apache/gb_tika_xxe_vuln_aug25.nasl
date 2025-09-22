# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155191");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-21 04:58:49 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2025-54988");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tika 1.13 - 3.2.1 XXE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_http_detect.nasl");
  script_mandatory_keys("apache/tika/detected");

  script_tag(name:"summary", value:"Apache Tika is prone to an XML external entity (XXE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"XXE in tika-parser-pdf-module allows an attacker to carry out
  XML External Entity injection via a crafted XFA file inside of a PDF. An attacker may be able to
  read sensitive data or trigger malicious requests to internal resources or third-party servers.

  Note that the tika-parser-pdf-module is used as a dependency in several Tika packages including
  at least: tika-parsers-standard-modules, tika-parsers-standard-package, tika-app, tika-grpc and
  tika-server-standard.");

  script_tag(name:"affected", value:"Apache Tika version 0.13 through 3.2.1.");

  script_tag(name:"solution", value:"Update to version 3.2.2 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/8xn3rqy6kz5b3l1t83kcofkw0w4mmj1w");


  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "0.13", test_version2: "3.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.2");
  security_message(port: port, data:report);
  exit(0);
}

exit(99);
