# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805051");
  script_cve_id("CVE-2015-2080");
  script_version("2024-06-12T05:05:44+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-12 05:05:44 +0000 (Wed, 12 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-08 11:29:00 +0000 (Fri, 08 Mar 2019)");
  script_tag(name:"creation_date", value:"2015-03-02 14:50:23 +0530 (Mon, 02 Mar 2015)");

  script_name("Jetty < 9.2.9.v20150224 Shared Buffers Information Leakage Vulnerability - Active Check");

  script_tag(name:"summary", value:"Jetty is prone to an information leakage vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw is triggered when handling 400 errors in HTTP
  responses. This may allow a remote attacker to gain access to potentially sensitive information in
  the memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information that may aid in further attacks.");

  script_tag(name:"affected", value:"Jetty versions 9.2.3 to 9.2.8 and beta releases of 9.3.x.");

  script_tag(name:"solution", value:"Update to version 9.2.9.v20150224 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Mar/12");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72768");
  script_xref(name:"URL", value:"http://dev.eclipse.org/mhonarc/lists/jetty-announce/msg00075.html");
  script_xref(name:"URL", value:"http://blog.gdssecurity.com/labs/2015/2/25/jetleak-vulnerability-remote-leakage-of-shared-buffers-in-je.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl");
  script_mandatory_keys("jetty/http/detected");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork:TRUE))
  exit(0);

host = http_host_name(port: port);

url = "/";
req =  string("POST ", url, " HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "Referer: ", raw_string(0x00), "\r\n",
              "Content-Length: 0\r\n\r\n");
res = http_send_recv(port: port, data: req);

if (res && res =~ "^HTTP/1\.[01] 400" && "Illegal character 0x0 in state=HEADER_VALUE" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  report += '\nResponse:\n' + res;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
