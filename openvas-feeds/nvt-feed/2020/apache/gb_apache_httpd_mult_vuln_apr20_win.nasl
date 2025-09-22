# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143672");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-04-03 02:56:02 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-09 11:15:00 +0000 (Fri, 09 Jul 2021)");

  script_cve_id("CVE-2020-1927", "CVE-2020-1934");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server 2.4.0 < 2.4.42 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Apache HTTP Server is prone to multiple vulnerabilities:

  - mod_rewrite CWE-601 open redirect (CVE-2020-1927)

  - mod_proxy_ftp use of uninitialized value (CVE-2020-1934)");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.0 to 2.4.41.");

  script_tag(name:"solution", value:"Update to version 2.4.42 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

affected = make_list("2.4.41",
                     "2.4.40",
                     "2.4.39",
                     "2.4.38",
                     "2.4.37",
                     "2.4.35",
                     "2.4.34",
                     "2.4.33",
                     "2.4.30",
                     "2.4.29",
                     "2.4.28",
                     "2.4.27",
                     "2.4.26",
                     "2.4.25",
                     "2.4.23",
                     "2.4.20",
                     "2.4.18",
                     "2.4.17",
                     "2.4.16",
                     "2.4.12",
                     "2.4.10",
                     "2.4.9",
                     "2.4.7",
                     "2.4.6",
                     "2.4.4",
                     "2.4.3",
                     "2.4.2",
                     "2.4.1",
                     "2.4.0");

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.4.42", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
