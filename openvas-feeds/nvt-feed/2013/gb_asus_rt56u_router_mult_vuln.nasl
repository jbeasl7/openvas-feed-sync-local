# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803715");
  script_version("2024-11-19T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-11-19 05:05:41 +0000 (Tue, 19 Nov 2024)");
  script_tag(name:"creation_date", value:"2013-06-11 13:49:12 +0530 (Tue, 11 Jun 2013)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ASUS RT56U Router Multiple Vulnerabilities (Jun 2013) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("RT-N56U/banner");

  script_tag(name:"summary", value:"ASUS RT56U Router is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaws are due to insufficient (or rather, a complete lack
  thereof) input sensitization leads to the injection of shell commands. It is possible to upload
  and execute a backdoor.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary shell commands and obtain the sensitive information.");

  script_tag(name:"affected", value:"Asus RT56U version 3.0.0.4.360 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/25998");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/asus-rt56u-remote-command-injection");
  script_xref(name:"URL", value:"http://forelsec.blogspot.in/2013/06/asus-rt56u-remote-command-injection.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);

if (!banner || 'WWW-Authenticate: Basic realm="RT-N56U"' >!< banner)
  exit(0);

url = "/Nologin.asp";

if (http_vuln_check(port: port, url: "/Nologin.asp", pattern: ">Login user IP:",
                    extra_check: make_list(">You cannot Login unless logout another user first",
                                           ">ASUS Wireless Router Web Manager<"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
