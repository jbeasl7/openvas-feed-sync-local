# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803720");
  script_version("2024-05-30T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-05-30 05:05:32 +0000 (Thu, 30 May 2024)");
  script_tag(name:"creation_date", value:"2013-06-25 12:51:19 +0530 (Tue, 25 Jun 2013)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("TRENDnet Print Server Authentication Bypass Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"TRENDnet Print Server is prone to an authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to a failure of the application to validate
  authentication credentials when processing print server configuration change requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to reset
  print server to factory settings or changing its IP address without password security check and
  obtain the sensitive information.");

  script_tag(name:"affected", value:"TRENDnet TE100-P1U Print Server Firmware version 4.11.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/26401");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/trendnet-te100-p1u-authentication-bypass");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (http_vuln_check(port: port, url: "/StsSys.htm", pattern: ">TRENDNET", extra_check: ">Printer",
                    usecache: TRUE)) {
  url = "/Network.htm";

  if (http_vuln_check(port: port, url: url, pattern: ">TRENDNET",
                      extra_check: make_list("IP Address<", "DNS Server Address<"))) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
