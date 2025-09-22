# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902472");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2011-3694");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("NetSaro Enterprise Messenger Server Source Code Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/104454/SERT-VDN-1012.txt");
  script_xref(name:"URL", value:"http://www.solutionary.com/index/SERT/Vuln-Disclosures/NetSaro-Enterprise-Messenger-Source-Code.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 4990);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to obtain
  access to the source code for the application and use information found to
  conduct further attacks against the application.");

  script_tag(name:"affected", value:"NetSaro Enterprise Messenger Server version 2.0 and prior.");

  script_tag(name:"insight", value:"The flaw exists due to error in administration console, allowing
  a remote attacker to obtain unauthenticated access to the applications source
  code. Attackers may make HTTP GET requests and append a Null Byte (%00) to
  allow download of the source code for the applications web pages.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"NetSaro Enterprise Messenger Server is prone to source code disclosure vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:4990);

rcvRes = http_get_cache(item:"/", port:port);

if("<title>NetSaro Administration Console</title>" >< rcvRes)
{
  sndReq = http_get(item:"/server-summary.nsp%00", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if(">System Summary</" >< rcvRes &&  ">Product Information</" >< rcvRes){
    security_message(port:port);
    exit(0);
  }
}

exit(99);
