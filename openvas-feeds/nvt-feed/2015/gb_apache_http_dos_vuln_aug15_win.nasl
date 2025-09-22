# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806000");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2015-0253");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2015-08-14 12:49:14 +0530 (Fri, 14 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache HTTP Server Denial Of Service Vulnerability (Aug 2015) - Windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to improper initialization of
  protocol structure member by 'read_request_line' function in
  'server/protocol.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service by sending a crafted request.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.12.");

  script_tag(name:"solution", value:"Update to version 2.4.13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.apache.org/dist/httpd/CHANGES_2.4");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75964");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_equal(version:vers, test_version:"2.4.12")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.13", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
