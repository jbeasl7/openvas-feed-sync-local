# SPDX-FileCopyrightText: 2002 Geoffroy Raimbault/Lynx Technologies
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11142");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Microsoft IIS 'IDC error' XSS Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (C) 2002 Geoffroy Raimbault/Lynx Technologies");
  script_family("Web Servers");
  script_dependencies("gb_microsoft_iis_http_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_xref(name:"URL", value:"http://online.securityfocus.com/bid/5900");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5900");
  script_xref(name:"URL", value:"http://www.ntbugtraq.com/default.asp?pid=36&sid=1&A2=ind0210&L=ntbugtraq&F=P&S=&P=1391");

  script_tag(name:"summary", value:"This IIS Server appears to be vulnerable to a Cross
Site Scripting due to an error in the handling of overlong requests on
an idc file. It is possible to inject Javascript
in the URL, that will appear in the resulting page.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
 of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
 disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

host = http_host_name(dont_add_port:TRUE);
if(http_get_has_generic_xss(port:port, host:host))
  exit(0);

# We construct the malicious URL with an overlong idc filename
filename = string("/<script></script>", crap(334), ".idc");
req = http_get(item:filename, port:port);

r = http_keepalive_send_recv(port:port, data:req);
str="<script></script>";
if((r =~ "^HTTP/1\.[01] 200" && str >< r)) security_message(port);
