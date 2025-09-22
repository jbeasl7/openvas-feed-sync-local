# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103286");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-10-05 13:15:09 +0200 (Wed, 05 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Easy Hosting Control Panel FTP Account Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49937");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Easy Hosting Control Panel is prone to a security-bypass
  vulnerability.");

  script_tag(name:"impact", value:"Attackers could exploit the issue to add arbitrary FTP accounts to the
  affected application.");

  script_tag(name:"affected", value:"Easy Hosting Control Panel versions 0.29.10 up to and including
  0.29.13 are vulnerable.");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

foreach dir(make_list_unique("/", http_cgi_dirs(port:port))) {

  buf = http_get_cache(item:dir + "/index.php", port:port);
  if(!buf || buf !~ "^HTTP/1\.[01] 200" || ("EHCP: An OpenSource" >!< buf && "ehcp, opensource, free, control" >!< buf && "?op=applyforaccount" >!< buf))
    continue;

  if( dir == "/" ) dir = "";
  url = string(dir, "/vhosts/ehcp/?op=applyforaccount");

  if(http_vuln_check(port:port, url:url, pattern:"Apply for ftp account", extra_check:'op=logout')) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
