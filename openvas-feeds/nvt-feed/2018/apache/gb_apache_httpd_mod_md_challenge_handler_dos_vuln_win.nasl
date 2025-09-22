# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813265");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2018-8011");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-07-20 15:20:23 +0530 (Fri, 20 Jul 2018)");
  script_name("Apache HTTP Server 'mod_md' Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in 'mod_md'
  challenge handler.Which is not properly handling the specially crafting HTTP
  requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to crash the Apache HTTP Server and perform a denial of service attack.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.33.");

  script_tag(name:"solution", value:"Update to version 2.4.34 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2018/q3/40");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2018-8011");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers == "2.4.33") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.34", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);