# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806799");
  script_version("2023-08-25T16:09:51+0000");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:C");
  script_tag(name:"last_modification", value:"2023-08-25 16:09:51 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2015-12-15 09:04:51 +0530 (Tue, 15 Dec 2015)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("WIMAX Modem Multiple Vulnerabilities (Dec 2015) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"WIMAX Modem is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - '/cgi-bin/diagnostic.cgi' fails to properly restrict access

  - '/cgi-bin/pw.cgi' fails to properly restrict access");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read
  sensitive information and set it on his own modem and send a packet to the modem for
  crashing/downgrading/DoS and to obtain the control of similar modem in order to launch DoS or
  DDoS attacks on targets.");

  script_tag(name:"affected", value:"WIMAX MT711x version V_3_11_14_9_CPE.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38914");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/cgi-bin/multi_wifi.cgi";

req = http_get(port: port, item: url);
res = http_send_recv(port: port, data: req);

if ("SeowonCPE" >< res && "wifi_mode" >< res && "auth_mode" >< res && "network_key" >< res &&
    "w_ssid" >< res && "wifi_setup" >< res && ">WiMAX" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
