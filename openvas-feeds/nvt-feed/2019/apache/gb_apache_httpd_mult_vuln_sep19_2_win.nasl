# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114148");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-10-18 15:43:41 +0200 (Fri, 18 Oct 2019)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");

  script_cve_id("CVE-2019-9517", "CVE-2019-10081");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server 2.4.20 - 2.4.39 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Apache HTTP server is prone to multiple vulnerabilities:

  - A malicious client could perform a DoS attack by flooding a connection with requests and
  basically never reading responses on the TCP connection. Depending on h2 worker dimensioning,
  it was possible to block those with relatively few connections. (CVE-2019-9517)

  - HTTP/2 very early pushes, for example configured with 'H2PushResource', could lead to
  an overwrite of memory in the pushing request's pool, leading to crashes. The memory
  copied is that of the configured push link header values, not data supplied by
  the client. (CVE-2019-10081)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.20 to 2.4.39.");

  script_tag(name:"solution", value:"Update to version 2.4.41 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version: version, test_version: "2.4.20", test_version2: "2.4.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.41", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
