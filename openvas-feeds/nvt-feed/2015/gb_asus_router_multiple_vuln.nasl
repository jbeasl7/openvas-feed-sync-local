# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805945");
  script_version("2024-03-08T15:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-08 15:37:10 +0000 (Fri, 08 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-08-05 13:27:24 +0530 (Wed, 05 Aug 2015)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-2676");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ASUS Router Multiple Vulnerabilities (Aug 2015) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("RT-G32/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"ASUS Router is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Flaws are exists as the application does not validate input
  passed via 'next_page', 'group_id', 'action_script', 'flag' parameters to start_apply.htm script
  before returning it to user.");

  script_tag(name:"impact", value:"Successful exploitation will allow a context-dependent attacker
  to create a specially crafted request that would execute arbitrary script code in a user's
  browser session within the trust relationship between their browser and the server and also to
  conduct CSRF attacks.");

  script_tag(name:"affected", value:"ASUS RT-G32 with firmware versions 2.0.2.6 and 2.0.3.2.
  Other firmware may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Mar/42");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73294");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port: port);

if (banner =~ 'WWW-Authenticate: Basic realm="RT-G32"') {
  url = "/start_apply.htm?next_page=%27%2balert(document.cookie)%2b%27";

  if (http_vuln_check(port:port, url:url, pattern:"alert\(document\.cookie\)",
                      extra_check:make_list("restart_time"))) {
    report = http_report_vuln_url( port:port, url:url );
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
