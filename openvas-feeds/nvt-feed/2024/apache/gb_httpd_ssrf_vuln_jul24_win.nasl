# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152690");
  script_version("2024-08-09T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-07-18 02:11:27 +0000 (Thu, 18 Jul 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-08 16:02:40 +0000 (Thu, 08 Aug 2024)");

  script_cve_id("CVE-2024-40898");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server 2.4.0 - 2.4.61 SSRF Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a server-side request forgery
  (SSRF) vulnerability with mod_rewrite in server/vhost context.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SSRF in Apache HTTP Server on Windows with mod_rewrite in
  server/vhost context, allows to potentially leak NTML hashes to a malicious server via SSRF and
  malicious requests.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.0 through 2.4.61.");

  script_tag(name:"solution", value:"Update to version 2.4.62 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/pcdvk1qfcqh17dpxz925p7ncy6j2ttwz");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html#2.4.62");

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

if (version_in_range(version: version, test_version: "2.4.0", test_version2: "2.4.61")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.62", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
