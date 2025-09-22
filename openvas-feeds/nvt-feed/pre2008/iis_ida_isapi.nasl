# SPDX-FileCopyrightText: 2001 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10695");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"IAVA", value:"2001-a-0008");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2880");
  script_cve_id("CVE-2001-0500");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft IIS .IDA ISAPI Filter Applied - Active Check");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2001 Matt Moore");
  script_family("Web Servers");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_tag(name:"summary", value:"Indexing Service filter is enabled on the remote Web server.");

  script_tag(name:"insight", value:"The IIS server appears to have the .IDA ISAPI filter mapped.

  At least one remote vulnerability has been discovered for the .IDA
  (indexing service) filter. This is detailed in Microsoft Advisory
  MS01-033, and gives remote SYSTEM level access to the web server.

  It is recommended that even if you have patched this vulnerability that
  you unmap the .IDA extension, and any other unused ISAPI extensions
  if they are not required for the operation of your site.");

  script_tag(name:"solution", value:"To unmap the .IDA extension:

  1.Open Internet Services Manager.

  2.Right-click the Web server choose Properties from the context menu.

  3.Master Properties

  4.Select WWW Service -> Edit -> HomeDirectory -> Configuration
  and remove the reference to .ida from the list.

  In addition, you may wish to download and install URLSCAN from the
  Microsoft Technet web site. URLSCAN, by default, blocks all .ida
  requests to the IIS server.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

req = http_get(item:"/NULL.ida", port:port);
soc = http_open_socket(port);
if(!soc)
  exit(0);

send(socket:soc, data:req);
r = http_recv(socket:soc);
http_close_socket(soc);
look = strstr(r, "<HTML>");
look = look - string("\r\n");
if(egrep(pattern:"^.*HTML.*IDQ.*NULL\.ida.*$", string:look))
  security_message(port);
