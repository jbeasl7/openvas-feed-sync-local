# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800942");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-10 15:23:12 +0200 (Thu, 10 Sep 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-7163");
  script_name("SineCMS Remote File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/4854");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27156");
  script_xref(name:"URL", value:"http://secunia.com/advisories/28305");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/39446");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sinecms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sinecms/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive
  information and execute arbitrary code via crafetd URLs which upload malicious files.");

  script_tag(name:"affected", value:"SineCMS version 2.3.5 and prior.");

  script_tag(name:"insight", value:"This vulnerability arises because input passed to the
  'sine[config][index_main]' parameter in 'mods/Integrated/index.php' is not
  sanitised before being used to include files.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"SineCMS is prone to a remote file inclusion vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

sinePort = http_get_port(default:80);

sineVer = get_kb_item("www/" + sinePort + "/SineCMS");
sineVer = eregmatch(pattern:"^(.+) under (/.*)$", string:sineVer);

if((!safe_checks()) && (sineVer[2] != NULL) )
{
  sndReq = http_get(item:string(sineVer[2], "/mods/Integrated/index.php?sine" +
  "[config][index_main]=../../Core/data/images/MALICIOUS.jpg%00"), port:sinePort);

  rcvRes = http_send_recv(port:sinePort, data:sndReq);
  if("MALICIOUS.jpg" >< rcvRes)
  {
    security_message(sinePort);
    exit(0);
  }
}

if(sineVer[1] != NULL)
{
  if(version_is_less_equal(version:sineVer[1], test_version:"2.3.5")){
     security_message(sinePort);
  }
}
