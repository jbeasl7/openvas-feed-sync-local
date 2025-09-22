# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808240");
  script_version("2024-04-05T15:38:49+0000");
  script_tag(name:"last_modification", value:"2024-04-05 15:38:49 +0000 (Fri, 05 Apr 2024)");
  script_tag(name:"creation_date", value:"2016-06-29 17:04:23 +0530 (Wed, 29 Jun 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ASUS DSL-N55U Router Multiple Vulnerabilities (Jun 2016) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("DSL-N55U/banner");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"ASUS DSL-N55U Router is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - An insufficient validation of user supplied input for the 'web path' in the 'httpd' binary,
  which redirect a user to the 'cloud_sync.asp' page with the web path as a value of a GET
  parameter.

  - An unauthenticated access to DHCP information of the local machines connected to the router
  from the WAN IP address.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  arbitrary web script into user's browser session and also to retrieve DHCP information including
  the hostname and private IP addresses of the local machines.");

  script_tag(name:"affected", value:"ASUS DSL-N55U router firmware version 3.0.0.4.376_2736.");

  script_tag(name:"solution", value:"Update to version 3.0.0.4_380_3679 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2016/Jun/97");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/538745");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

banner = http_get_remote_headers(port: port);

if ('WWW-Authenticate: Basic realm="DSL-N55U' >!< banner)
  exit(0);

url = "/111111111111111111111111111111111111111<script>alert(document.cookie)</script>";

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern: "<script>alert\(document\.cookie\)</script>",
                    extra_check: make_list("cloud_sync.asp\?flag", ">location"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
