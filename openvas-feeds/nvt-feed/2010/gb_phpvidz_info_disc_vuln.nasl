# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801549");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHPvidz Administrative Credentials Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2010/May/129");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15606/");
  script_xref(name:"URL", value:"http://www.mail-archive.com/bugtraq@securityfocus.com/msg33846.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"phpvidz uses a system of flat files to maintain application
state. The administrative password is stored within the '.inc' file and
is included during runtime.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"PHPvidz is prone to administrative credentials disclosure vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to
obtain sensitive information.");

  script_tag(name:"affected", value:"PHPvidz version 0.9.5");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

foreach dir( make_list_unique( "/phpvidz_0.9.5", "/phpvidz", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  res = http_get_cache(item:string(dir, "/index.php"), port:port);

  if(">PHPvidz<" >< res)
  {
    if(http_vuln_check(port:port, url:dir + "/includes/init.inc",
                       pattern:"(define .'ADMINPASSWORD)"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}
