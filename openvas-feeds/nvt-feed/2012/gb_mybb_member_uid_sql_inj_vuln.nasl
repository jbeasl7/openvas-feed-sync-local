# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802636");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-06-08 12:12:12 +0530 (Fri, 08 Jun 2012)");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("MyBB 'member.php' SQLi Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mybb/http/detected");

  script_tag(name:"summary", value:"MyBB is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"insight", value:"The application fails to sufficiently sanitize user supplied
  input to the 'uid' parameter in 'member.php' before using it in an SQL query, which allows
  attackers to execute arbitrary SQL commands in the context of an affected site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to
  compromise the application, access or modify data or exploit vulnerabilities in the
  underlying database.");

  script_tag(name:"affected", value:"MyBB version 1.6.8.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53814");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/76097");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113300/mybb168-sql.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/member.php?action=profile&uid='";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
  pattern: "You have an error in your SQL syntax",
  extra_check: "MyBB has experienced an internal SQL error"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
