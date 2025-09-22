# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100059");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-03-18 12:46:43 +0100 (Wed, 18 Mar 2009)");
  script_cve_id("CVE-2009-0862");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("TangoCMS 'listeners.php' Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more
  information.");

  script_tag(name:"summary", value:"TangoCMS is prone to a cross-site scripting vulnerability because it fails to
  sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code in the
  browser of an unsuspecting user in the context of the affected site. This may
  allow the attacker to steal cookie-based authentication credentials and to
  launch other attacks.");

  script_tag(name:"affected", value:"Versions prior to TangoCMS 2.2.4 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33833");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("version_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/tangocms", "/cms", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, '/README');
  buf = http_get_cache(item:url, port:port);
  if( ! buf ) continue;

  if (egrep(pattern:".*TangoCMS.*", string: buf, icase: TRUE) ) {
    version = eregmatch(string: buf, pattern: "\* Version, ([0-9]+\.*[0-9]*\.*[0-9]*)");
    if(!isnull(version[1])) {
      if(version_is_less(version:version[1], test_version:"2.2.4")){
        report = report_fixed_ver(installed_version:version[1], fixed_version:"2.2.4");
        security_message(port: port, data: report);
        exit(0);
      }
    }
  }
}

exit( 99 );
