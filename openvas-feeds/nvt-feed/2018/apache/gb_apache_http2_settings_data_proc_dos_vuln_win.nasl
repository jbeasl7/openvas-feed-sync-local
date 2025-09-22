# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814057");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2018-11763");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-09-28 11:02:47 +0530 (Fri, 28 Sep 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache HTTP Server HTTP/2 'SETTINGS' Data Processing DoS Vulnerability - Windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper processing of
  specially crafted and continuous SETTINGS data for an ongoing HTTP/2 connection
  to cause the target service to fail to timeout.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (DoS) condition on a targeted system.");

  script_tag(name:"affected", value:"Apache HTTP Server versions 2.4.34, 2.4.33,
  2.4.30, 2.4.29, 2.4.28, 2.4.27, 2.4.26, 2.4.25, 2.4.23, 2.4.20, 2.4.18.");

  script_tag(name:"solution", value:"Update to Apache HTTP Server 2.4.35 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://securitytracker.com/id/1041713");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

if(vers =~ "^2\.4") {
  foreach affected_version (make_list("2.4.18", "2.4.20", "2.4.23", "2.4.25", "2.4.26", "2.4.27", "2.4.28", "2.4.29", "2.4.30", "2.4.33", "2.4.34")) {
    if(affected_version == vers) {
      report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.35", install_path:path);
      security_message(data:report, port:port);
      exit(0);
    }
  }
}

exit(99);
