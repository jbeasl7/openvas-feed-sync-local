# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phplist:phplist";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103231");
  script_version("2025-05-20T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-20 05:40:25 +0000 (Tue, 20 May 2025)");
  script_tag(name:"creation_date", value:"2011-08-29 15:19:27 +0200 (Mon, 29 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("PHPList Security Bypass and Information Disclosure Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49188");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/519295");

  script_tag(name:"qod_type", value:"remote_vul");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_phplist_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phplist/http/detected");

  script_tag(name:"summary", value:"PHPList is prone to a security bypass vulnerability and an
  information disclosure vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to gain access to sensitive
  information and send arbitrary messages to registered users. Other attacks are also possible.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

for (i=1; i<50; i++) {
  url = dir + "/lists/?p=forward&uid=foo&mid=" + i;

  if (http_vuln_check(port: port, url: url, pattern:"Forwarding the message with subject")) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
