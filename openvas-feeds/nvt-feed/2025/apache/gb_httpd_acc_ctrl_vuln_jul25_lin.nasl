# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154911");
  script_version("2025-07-11T15:43:14+0000");
  script_tag(name:"last_modification", value:"2025-07-11 15:43:14 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-11 02:58:47 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2025-23048");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server 2.4.35 < 2.4.64 Access Control Bypass Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to an access control bypass
  vulnerability in mod_ssl.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In some mod_ssl configurations an access control bypass by
  trusted clients is possible using TLS 1.3 session resumption.

  Configurations are affected when mod_ssl is configured for multiple virtual hosts, with each
  restricted to a different set of trusted client certificates (for example with a different
  SSLCACertificateFile/Path setting). In such a case, a client trusted to access one virtual host
  may be able to access another virtual host, if SSLStrictSNIVHostCheck is not enabled in either
  virtual host.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.35 through 2.4.63.");

  script_tag(name:"solution", value:"Update to version 2.4.64 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html#2.4.64");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE,
                                          version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "2.4.35", test_version_up: "2.4.64")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.64", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
