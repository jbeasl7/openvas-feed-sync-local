# SPDX-FileCopyrightText: 2001 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10778");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_name("Unprotected SiteScope Service (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 Digital Defense Inc.");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl",
                      "gb_default_credentials_options.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8888);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Make sure that a password is set in the configuration
  for this service. Depending on where this server is located,
  you may want to restrict access by IP address in addition to
  username.");

  script_tag(name:"summary", value:"The SiteScope web service has no password set. An attacker
  who can connect to this server could view usernames and
  passwords stored in the preferences section or reconfigure
  the service.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8888 );

url = "/SiteScope/cgi/go.exe/SiteScope?page=eventLog&machine=&logName=System&account=administrator";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( "Event Log" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report);
  exit( 0 );
}

exit( 0 );
