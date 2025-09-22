# SPDX-FileCopyrightText: 2001 Javier Fernandez-Sanguino Pena
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10781");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-0660");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Outlook Web anonymous access");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 Javier Fernandez-Sanguino Pena");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://support.microsoft.com/support/exchange/content/whitepapers/owaguide.doc");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3301");

  script_tag(name:"solution", value:"Disable anonymous access to OWA. Follow these steps:

  1. In Microsoft Exchange Administrator open the Configuration container.

  2. Choose Protocols, and then double-click HTTP (Web) Site Settings

  3. Deselect the 'Allow anonymous users to access the anonymous public folders' check box.

  4. Select the Folder Shortcuts tab.

  5. Remove all folders which are allowed anonymous viewing.

  6. Choose OK.

  7. Remove the anonymous access from the login web pages.");

  script_tag(name:"summary", value:"It is possible to browse the information of the OWA server by accessing as an
  anonymous user.");

  script_tag(name:"insight", value:"Accessing as an anonymous user is possible with the following URL:

  http://www.example.com/exchange/root.asp?acs=anon

  After this access, the anonymous user can search for valid users in the OWA
  server and can enumerate all users by accessing the following URL:

  http://www.example.com/exchange/finduser/details.asp?obj=XXX (where XXX is a string of 65 hexadecimal numbers)");

  script_tag(name:"impact", value:"Data that can be accessed by an anonymous user may include: usernames, server names,
  email name accounts, phone numbers, departments, office, management relationships...

  This information will help an attacker to make social engineering attacks with the knowledge gained. This attack
  can be easily automated since, even if direct access to search is not possible, you only need the cookie given on
  the anonymous login access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if ( ! http_can_host_asp(port:port) )
  exit(0);

cgi = "/exchange/root.asp?acs=anon";
if(!http_is_cgi_installed_ka(item:cgi, port:port))
  exit(0);

req = http_get(item:cgi, port:port);
r = http_keepalive_send_recv(port:port, data:req);
if(! r || "/exchange/logonfrm.asp" >!< r)
  exit(0);

req = http_get(item:"/exchange/logonfrm.asp", port:port);
r = http_keepalive_send_recv(port:port, data:req);
if(r && "This page has been disabled" >!< r) {
  report = http_report_vuln_url(port:port, url:cgi);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
