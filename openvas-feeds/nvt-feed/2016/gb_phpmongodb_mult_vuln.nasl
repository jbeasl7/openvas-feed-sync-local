# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:mongodb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807554");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-04-25 11:53:15 +0530 (Mon, 25 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("PHPmongoDB CSRF And XSS Vulnerabilities");

  script_tag(name:"summary", value:"PHPmongoDB is prone to multiple cross-site scripting (XSS) and
  cross-site request forgery (CSRF) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due,

  - The multiple cross-site request forgery (CSRF) vulnerabilities in the
    index.php script which can be exploited via different vectors.

  - An insufficient validation of user-supplied input via GET parameters
    'URL', 'collection', 'db' and POST parameter 'collection' in index.php
    script and other parameters may be also affected.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session, and to
  conduct request forgery attacks.");

  script_tag(name:"affected", value:"PHPmongoDB version 1.0.0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136686");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmongodb_remote_detect.nasl");
  script_mandatory_keys("PHPmongoDB/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!mongoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mongodir = get_app_location(cpe:CPE, port:mongoPort)){
  exit(0);
}

if(mongodir == "/"){
  mongodir = "";
}

mongourl = mongodir + '/index.php/"><script>alert(document.cookie)</script>';

if(http_vuln_check(port:mongoPort, url:mongourl, check_header:TRUE,
                   pattern:"<script>alert\(document.cookie\)</script>",
                   extra_check:make_list('content="mongoDB', 'PHPmongoDB.org',
                                         '>Sign In')))
{
  report = http_report_vuln_url( port:mongoPort, url:mongourl );
  security_message(port:mongoPort, data:report);
  exit(0);
}
