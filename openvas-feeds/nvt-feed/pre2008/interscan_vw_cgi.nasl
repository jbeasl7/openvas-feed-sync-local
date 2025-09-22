# SPDX-FileCopyrightText: 2001 INTRANODE
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10733");
  script_version("2024-08-09T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2579");
  script_cve_id("CVE-2001-0432");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("InterScan VirusWall Remote Configuration Vulnerability");
  script_category(ACT_ATTACK); # nb: Direct access to a .dll file might be already seen as an attack
  script_copyright("Copyright (C) 2001 INTRANODE");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Don't connect the management interface directly to the Internet.");

  script_tag(name:"summary", value:"The management interface used with the Interscan VirusWall
  uses several cgi programs that may allow a malicious user to remotely change the configuration
  of the server without any authorization using maliciously constructed querystrings.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = "/interscan/cgi-bin/FtpSave.dll?I'm%20Here";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( "These settings have been saved" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
