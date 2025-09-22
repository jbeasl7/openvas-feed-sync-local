# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804470");
  script_version("2025-05-14T05:40:11+0000");
  script_tag(name:"last_modification", value:"2025-05-14 05:40:11 +0000 (Wed, 14 May 2025)");
  script_tag(name:"creation_date", value:"2014-06-25 12:28:41 +0530 (Wed, 25 Jun 2014)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-28 01:42:00 +0000 (Fri, 28 Feb 2020)");

  script_cve_id("CVE-2014-4018", "CVE-2014-4019", "CVE-2014-4154", "CVE-2014-4155");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ZTE WXV10 W300 Multiple Vulnerabilities (Jan 2014) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ZXV10_W300/banner");

  script_tag(name:"summary", value:"ZTE WXV10 W300 router is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The 'admin' account has a password of 'admin', which is publicly known and documented. This
  allows remote attackers to trivially gain privileged access to the device.

  - Flaw in /basic/home_wan.htm that is triggered as the device exposes the device password in the
  source of the page when a user authenticates to the device.

  - The HTTP requests to /Forms/tools_admin_1 do not require multiple steps, explicit confirmation,
  or a unique token when performing certain sensitive actions.

  - The rom-0 backup file contains sensitive information such as the router password. There is a
  disclosure in which anyone can download that file without any authentication by a simple GET
  request.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to trivially
  gain privileged access to the device, execute arbitrary commands and gain access to arbitrary
  files.");

  script_tag(name:"affected", value:"ZTE ZXV10 W300 routers.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33803");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68082");
  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2014/01/23/zte-zxv10-w300-router-multiple-vulnerabilities");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if ('WWW-Authenticate: Basic realm="ZXV10 W300"' >!< banner)
  exit(0);

url = "/rom-0";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

## http_vuln_check() is not working
if ("dbgarea" >< res && "spt.dat" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
