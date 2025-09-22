# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804475");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-07-21 12:35:29 +0530 (Mon, 21 Jul 2014)");
  script_name("ZKSoftware WebServer Default Admin Credentials (HTTP)");

  script_tag(name:"summary", value:"The ZKSoftware WebServer is using default admin credentials.");

  script_tag(name:"vuldetect", value:"Send a crafted default admin credentials via HTTP POST request and check
  whether it is possible to login or not.");

  script_tag(name:"insight", value:"It was possible to login with default credentials.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to gain access to sensitive
  information or modify system configuration.");

  script_tag(name:"affected", value:"ZKSoftware WebServer.");

  script_tag(name:"solution", value:"Change the default credentials.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_xref(name:"URL", value:"http://blog.infobytesec.com/2014/07/perverting-embedded-devices-zksoftware_2920.html");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ZK_Web_Server/banner");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port: port);
if(!banner || banner !~ "Server\s*:\s*ZK Web Server")
  exit(0);

host = http_host_name(port:port);

postdata = "username=administrator&userpwd=123456";
req = string("POST /csl/check HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postdata), "\r\n\r\n",
             postdata);
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && ">Department Name<" >< res &&
   ">Privilege<" >< res && ">Name<" >< res) {
   security_message(port:port);
   exit(0);
}

exit(99);
