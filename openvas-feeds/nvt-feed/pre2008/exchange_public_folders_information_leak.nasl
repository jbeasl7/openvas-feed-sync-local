# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10755");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-0660");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Microsoft Exchange Public Folders Information Leak");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/windowsntfocus/5WP091P5FQ.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3301");

  script_tag(name:"summary", value:"Microsoft Exchange Public Folders can be set to allow anonymous connections (set by default).
  If this is not changed it is possible for an attacker to gain critical information about the users (such as full email address,
  phone number, etc) that are present in the Exchange Server.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if( ! http_can_host_asp(port:port) )
  exit(0);

host = http_host_name(port:port);

res = http_is_cgi_installed_ka(item:"/exchange/root.asp", port:port);
if(!res)
  exit(0);

first = http_get(item:"/exchange/root.asp?acs=anon", port:port);
result = http_keepalive_send_recv(data:first, port:port);
if(!result)
  exit(0);

if((egrep(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:result)) && ("Set-Cookie: " >< result) && ("top.location='/exchange/logonfrm.asp'" >< result)) {

  SetCookie = strstr(result, "Set-Cookie: ");
  resultsub = strstr(SetCookie, "; path=/");
  SetCookie = SetCookie - "Set-Cookie: ";
  SetCookie = SetCookie - resultsub;

  second = string("GET /exchange/logonfrm.asp HTTP/1.1\r\nHost: ", host, "\r\nCookie: ", SetCookie, "\r\n\r\n");
  result = http_keepalive_send_recv(data:second, port:port);
  if(!result)
    exit(0);

  if((egrep(pattern:"^HTTP/[0-9]\.[0-9] 302 .*", string:result)) && ("Location: /exchange/root.asp?acs=anon" >< result)) {

    third = string("GET /exchange/root.asp?acs=anon HTTP/1.1\r\nHost: ", host, "\r\nCookie: ", SetCookie, "\r\n\r\n");
    result = http_keepalive_send_recv(data:third, port:port);
    if(!result)
      exit(0);

    if((egrep(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:result)) && ("/exchange/Navbar/nbAnon.asp" >< result)) {

      final = string("POST /exchange/finduser/fumsg.asp HTTP/1.1\r\nHost: ", host, "\r\nAccept: */*\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 44\r\nCookie: ", SetCookie, "\r\n\r\nDN=a&FN=&LN=&TL=&AN=&CP=&DP=&OF=&CY=&ST=&CO=");
      result = http_keepalive_send_recv(data:final, port:port);
      if(!result)
        exit(0);

      if((egrep(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:result)) && (("details.asp?obj=" >< result) || ("This query would return" >< result)) ) {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);
