# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11083");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-0839");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3476");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ibillpm.pl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The 'ibillpm.pl' CGI is installed.

  Some versions of this CGI use a weak password management system
  that can be brute-forced.");

  script_tag(name:"solution", value:"Upgrade the script if possible. If not:

  1) Move the script elsewhere (security through obscurity)

  2) Request that iBill fix it.

  3) Configure your web server so that only addresses from ibill.com
  may access it.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

# Note: we could try to access it. If we get a 403 the site is safe.
res = http_is_cgi_installed_ka(item:"ibillpm.pl", port:port);
if(res) {
  security_message(port:port);
  exit(0);
}

exit(99);
