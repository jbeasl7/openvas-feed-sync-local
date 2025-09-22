# SPDX-FileCopyrightText: 2003 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11939");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0762");
  script_name("foxweb <= 2.5 CGI Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210313101631/http://www.securityfocus.com/bid/8547");

  script_tag(name:"summary", value:"The foxweb.dll or foxweb.exe CGI is installed.

  Versions 2.5 and below of this CGI program have a security flaw
  that lets an attacker execute arbitrary code on the remote server.");

  script_tag(name:"vuldetect", value:"Checks if the CGI is installed on the remote host.");

  script_tag(name:"solution", value:"Remove it from /cgi-bin or upgrade it.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

foreach cgi( make_list( "foxweb.dll", "foxweb.exe") ) {

  res = http_is_cgi_installed_ka( item:cgi, port:port );
  if( res ) {
    report = http_report_vuln_url( port:port, url:"/" + cgi );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
