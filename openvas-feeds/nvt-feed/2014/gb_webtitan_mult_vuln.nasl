# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804469");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2014-4306", "CVE-2014-4307");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-06-23 18:10:58 +0530 (Mon, 23 Jun 2014)");
  script_name("WebTitan Multiple Security Vulnerabilities");

  script_tag(name:"summary", value:"WebTitan is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted default credential via HTTP GET request and check whether it
  is able to get information or not.");

  script_tag(name:"insight", value:"- The categories-x.php script not properly sanitizing user-supplied input to
  the 'sortkey' GET parameter.

  - Input passed via the 'fname' and 'logfile' parameters is not properly
  sanitized upon submission to logs-x.php.

  - Input passed via the 'ldapserver' parameter is not properly sanitized
  upon submission to the users-x.php script.

  - Input passed via the 'ntpserversList' POST parameter is not properly
  sanitized upon submission to the time-x.php script.

  - Input passed via the 'reportid' parameter is not properly sanitized upon
  submission to the schedulereports-x.php script.

  - Input passed via the 'delegated_admin' POST parameter is not properly
  sanitized upon submission to the reporting-x.php script.

  - The autoconf-x.php, contentfiltering-x.php, license-x.php, msgs.php, and
  reports-drill.php scripts not requiring authentication.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to trivially gain privileged
  access to the device, execute arbitrary commands and gain access to arbitrary files.");

  script_tag(name:"affected", value:"WebTitan version 4.01 (Build 68).");

  script_tag(name:"solution", value:"Upgrade to WebTitan version 4.04 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33699");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67921");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/35");
  script_xref(name:"URL", value:"http://bot24.blogspot.in/2014/06/sec-consult-sa-20140606-0-multiple.html");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

kPort = http_get_port(default:80);
if(!http_can_host_php(port:kPort))
  exit(0);

webRes = http_get_cache(item:"/login.php",  port:kPort);

if(">WebTitan<" >< webRes && "Copperfasten Technologies" >< webRes)
{
  url = '/categories-x.php?getcategories&sortkey=name)%20limit%205;--';

  if(http_vuln_check(port:kPort, url:url, check_header:TRUE,
     pattern: "records.:.*categoryid.:.*:.SYSTEM",
     extra_check:"totalRecords"))
  {
    security_message(kPort);
    exit(0);
  }
}
