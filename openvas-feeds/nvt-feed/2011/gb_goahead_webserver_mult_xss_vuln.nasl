# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:embedthis:goahead";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902589");
  script_version("2025-07-30T05:45:23+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-07-30 05:45:23 +0000 (Wed, 30 Jul 2025)");
  script_tag(name:"creation_date", value:"2011-11-23 12:12:12 +0530 (Wed, 23 Nov 2011)");

  script_cve_id("CVE-2023-53155");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Embedthis GoAhead 2.5 'name' and 'address' XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_embedthis_goahead_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("embedthis/goahead/http/detected");

  script_tag(name:"summary", value:"Embedthis GoAhead is prone to multiple cross-site scripting
  (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied
  input via the 'name' and 'address' parameters in goform/formTest, which allows attackers to
  execute arbitrary HTML and script code in a user's browser session in the context of an affected
  site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"Embedthis GoAhead version 2.5 is known to be affected. Other
  versions might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20121024093547/http://secunia.com/advisories/46896");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121220147/http://www.securityfocus.com/bid/50729");
  script_xref(name:"URL", value:"https://web.archive.org/web/20111115133941/http://webserver.goahead.com/forum/topic/169");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/51762");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/goform/formTest?name=<script>alert(document.cookie)</script>";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"Name: <script>alert\(document\.cookie\)</script>")){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
