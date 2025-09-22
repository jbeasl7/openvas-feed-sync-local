# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:buffalo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103617");
  script_version("2023-09-20T05:05:13+0000");
  script_tag(name:"last_modification", value:"2023-09-20 05:05:13 +0000 (Wed, 20 Sep 2023)");
  script_tag(name:"creation_date", value:"2012-12-03 17:27:36 +0100 (Mon, 03 Dec 2012)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Since it is not clear which devices are affected, we check all Buffalo NAS, not only LinkStation
  script_name("Buffalo Linkstation Privilege Escalation / Information Disclosure (Dec 2012)");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_buffalo_nas_http_detect.nasl");
  script_mandatory_keys("buffalo/nas/detected");

  script_tag(name:"summary", value:"Buffalo Linkstation devices suffer from information disclosure
  and privilege escalation vulnerabilities.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118532/Buffalo-Linkstation-Privilege-Escalation-Information-Disclosure.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

port = infos["port"];
CPE  = infos["cpe"];

if( ! dir = get_app_location( port:port, cpe:CPE ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = "/modules/webaxs/module/files/password";

if( http_vuln_check( port:port, url:url, pattern:"[a-zA-Z0-9.-_]+:[[a-zA-Z0-9.$/-_]+", check_header:TRUE, extra_check:"text/plain" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
