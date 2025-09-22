# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100614");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-04-30 13:41:49 +0200 (Fri, 30 Apr 2010)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Mini Web Server Cross Site Scripting and Directory Traversal Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39780");
  script_xref(name:"URL", value:"http://www.jibble.org/miniwebserver/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("JibbleWebServer/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Mini Web Server is prone to a directory traversal vulnerability and a
  cross-site scripting vulnerability because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting these issues will allow an attacker to execute arbitrary
  script code in the browser of an unsuspecting user in the context of
  the affected site, and to view arbitrary local files and directories
  within the context of the webserver. This may let the attacker steal
  cookie-based authentication credentials and other harvested
  information may aid in launching further attacks.");

  script_tag(name:"affected", value:"Mini Web Server 1.0 is vulnerable, other versions may also be
  affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port: port);
if(!banner || "Server: JibbleWebServer" >!< banner)
  exit(0);

version = eregmatch(pattern:"Server: JibbleWebServer/([0-9.]+)", string:banner);
if(isnull(version[1]))exit(0);

if(version_is_equal(version: version[1], test_version:"1.0")) {
  security_message(port:port);
  exit(0);
}

exit(0);
