# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:froxlor:froxlor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106036");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2015-08-03 13:44:55 +0700 (Mon, 03 Aug 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-07 19:53:00 +0000 (Thu, 07 Sep 2017)");

  script_cve_id("CVE-2015-5959");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Froxlor Information Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_froxlor_http_detect.nasl");
  script_mandatory_keys("froxlor/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Froxlor is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted GET request and check the response.");

  script_tag(name:"insight", value:"An unauthenticated remote attacker is able to get the database
  password via webaccess due to wrong file permissions of the /logs/ folder. The plain SQL password
  and username may be stored in the /logs/sql-error.log file.");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may be able to get the plain
  SQL password and username or other sensitive information.");

  script_tag(name:"affected", value:"Froxlor version 0.9.33.1 and prior.");

  script_tag(name:"solution", value:"Update to version 0.9.33.2 or later.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/07/29/8");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/logs/sql-error.log";
req = http_get(item: url, port: port);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

if (res =~ "^HTTP/1\.[01] 200" && "SQLSTATE[HY000]" >< res) {
  report = http_report_vuln_url( port:port, url:url );
  security_message(port: port, data:report);
  exit(0);
}

exit(0);
