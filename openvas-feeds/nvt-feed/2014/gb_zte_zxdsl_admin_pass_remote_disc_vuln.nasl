# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804798");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-11-14 16:42:38 +0530 (Fri, 14 Nov 2014)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2014-9184", "CVE-2014-9183");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ZTE ZXDSL Modem Information Disclosure Vulnerability (Nov 2014) - Active Check");

  # nb: Just a standard HTTP request a user would do as well so no ACT_ATTACK needed...
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"ZTE ZXDSL modem devices are prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to the source information of /adminpasswd.cgi
  script displays admin password information in cleartext.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
  access to admin password information.");

  script_tag(name:"affected", value:"ZTE ZXDSL 831CI modem devices are known to be affected. Other
  models or vendors might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://seclists.org/bugtraq/2014/Nov/40");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/35203");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210116142834/http://www.securityfocus.com/archive/1/533929/30/0/threaded");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/adminpasswd.cgi";

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern: ">Admin account.*configuration of your ADSL<",
                    extra_check: make_list(">User Name:<", ">New Password:<",
                                           ">Admin Account<", "btnApplyAdmin"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
