# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805067");
  script_version("2023-09-13T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-09-13 05:05:22 +0000 (Wed, 13 Sep 2023)");
  script_tag(name:"creation_date", value:"2015-04-29 12:50:10 +0530 (Wed, 29 Apr 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2015-3447");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Dell SonicWALL SonicOS XSS Vulnerability (Apr 2015) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("SonicWALL/banner");

  script_tag(name:"summary", value:"Dell SonicWALL SonicOS is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"This flaw exists because the /macIpSpoofView.html script does
  not validate input to the 'searchSpoof' and 'searchSpoofIpDet' GET parameters before returning it
  to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to create a
  specially crafted request that would execute arbitrary script code in a user's browser session
  within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Dell SonicWall SonicOS version 6.x and 7.5.0.12. Other
  versions might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/535393");
  script_xref(name:"URL", value:"http://www.vulnerability-lab.com/get_content.php?id=1359");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if (!banner || "Server: SonicWALL" >!< banner)
  exit(0);

url = "/macIpSpoofView.html?mainFrameYAxis=0&startItem=0&startItemIpDet=0" +
      "&currIfaceConfig=0&currIfaceConfigIndex=1&searchSpoof=[x]&searchSp" +
      "oofIpDet=%22%3E%3Ciframe%20src%3Da%20onload%3Dalert(document.cookie)";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && "><iframe src=a onload=alert(document.cookie)" >< res  &&
    "MAC-IP Anti-Spoof" >< res && "Spoof Detection" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
