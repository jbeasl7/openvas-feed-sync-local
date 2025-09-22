# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804872");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2014-8363", "CVE-2014-8364");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-10-29 15:09:33 +0530 (Wed, 29 Oct 2014)");

  script_name("WordPress Spreadsheet plugin Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The WordPress plugin 'Spreadsheet' is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Input passed via the 'ss_id' parameter to
  wpSS/ss_handler.php script is not validated before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site and inject or manipulate SQL queries in the
  back-end database, allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"WordPress Spreadsheet plugin version 0.62");

  script_tag(name:"solution", value:"No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none
  will be provided anymore. General solution options are to upgrade to a
  newer release, disable respective features, remove the product or replace
  the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127770");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69073");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69089");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/wpSS/ss_handler.php?ss_id=%22/%3E%3Cscri" +
            "pt%3Ealert%28document.cookie%29;%3C/script%3E";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
  pattern:"<script>alert\(document\.cookie\);</script>",
  extra_check:">WordPress Spreadsheet"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}
