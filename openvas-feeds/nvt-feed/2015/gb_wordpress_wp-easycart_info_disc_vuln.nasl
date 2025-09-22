# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805124");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2014-4942");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-13 12:25:08 +0530 (Tue, 13 Jan 2015)");
  script_name("WordPress EasyCart Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"WordPress EasyCart is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read system info or not.");

  script_tag(name:"insight", value:"Flaw is due to improper handling of a
  direct request for the /inc/admin/phpinfo.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to disclose detailed system information.");

  script_tag(name:"affected", value:"WordPress EasyCart version 2.0.1
  through 2.0.5");

  script_tag(name:"solution", value:"Update to version 2.0.6 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://codevigilant.com/disclosure/wp-plugin-wp-easycart-information-disclosure");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68692");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-easycart");
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

url = dir + '/wp-content/plugins/wp-easycart/inc/admin/phpinfo.php';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
  pattern:">phpinfo\(\)<", extra_check:make_list(">System", ">Configuration File"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
