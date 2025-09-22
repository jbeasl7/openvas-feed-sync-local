# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112904");
  script_version("2024-03-13T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-03-13 05:05:57 +0000 (Wed, 13 Mar 2024)");
  script_tag(name:"creation_date", value:"2021-06-10 09:23:11 +0000 (Thu, 10 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-17 08:15:00 +0000 (Sat, 17 Jul 2021)");

  script_cve_id("CVE-2021-31618");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server 2.4.47 NULL Pointer Dereference Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a NULL pointer dereference
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Apache HTTP Server protocol handler for the HTTP/2 protocol
  checks received request headers against the size limitations as configured for the server and used
  for the HTTP/1 protocol as well. On violation of these restrictions an HTTP response is sent to
  the client with a status code indicating why the request was rejected.

  This rejection response was not fully initialised in the HTTP/2 protocol handler if the offending
  header was the very first one received or appeared in a footer. This led to a NULL pointer
  dereference on initialised memory, crashing reliably the child process.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to crash the
  server.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.47 only.");

  script_tag(name:"solution", value:"Update to version 2.4.48 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_equal( version:version, test_version:"2.4.47" ) ) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.4.48", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
