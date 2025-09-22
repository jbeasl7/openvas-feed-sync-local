# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808663");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2016-08-23 18:12:02 +0530 (Tue, 23 Aug 2016)");
  script_name("C2S DVR Management Credentials Disclosure and Authentication Bypass Vulnerabilities");

  script_tag(name:"summary", value:"C2S DVR Management application is prone to credentials disclosure and authentication bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists due to an improper
  restriction on user access levels for certain pages.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to disclose the username and password and also to change the admin
  password.");

  script_tag(name:"affected", value:"C2S DVR Management camera types IRDOME-II-C2S,
  IRBOX-II-C2S, DVR.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40265");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

c2sPort = http_get_port(default:80);

rcvRes = http_get_cache(item:"/", port:c2sPort);

## Application confirmation for more specific is not possible,
## hence not going for detect VT
if(rcvRes =~ "^HTTP/1\.[01] 200" &&  "cash.png" >< rcvRes &&
   "password error" >< rcvRes)
{

  url = "/cgi-bin/read.cgi?page=2";

  if(http_vuln_check(port:c2sPort, url:url,  pattern:'var pw_adminpw',
                     check_header:TRUE, extra_check:make_list('var pw_userpw',
                    'var pw_autolock', 'var pw_enflag')))
  {
    report = http_report_vuln_url(port:c2sPort, url:url);
    security_message(port:c2sPort, data:report);
    exit(0);
  }
}
