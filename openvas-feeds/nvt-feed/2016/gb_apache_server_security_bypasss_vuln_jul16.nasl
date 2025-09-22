# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807855");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2016-4979");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");
  script_tag(name:"creation_date", value:"2016-07-08 12:07:29 +0530 (Fri, 08 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache HTTP Server Security Bypass Vulnerability (Jul 2016)");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw affects servers that have http/2
  enabled and use TLS client certificates for authentication. It is due to have
  forgotten the return to the original verify_mode when released to the connection
  of the HTTP/1.1");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass the client authentication at the time of HTTP/2 use.");

  script_tag(name:"affected", value:"Apache HTTP Server 2.4.18 through 2.4.20,
  when mod_http2 and mod_ssl are enabled.");

  script_tag(name:"solution", value:"Update to version 2.4.23 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://d.hatena.ne.jp/jovi0608/20160706/1467800335");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91566");
  script_xref(name:"URL", value:"https://mail-archives.apache.org/mod_mbox/httpd-announce/201607.mbox/CVE-2016-4979-68283");
  script_xref(name:"URL", value:"https://isc.sans.edu/forums/diary/Apache+Update+TLS+Certificate+Authentication+Bypass+with+HTTP2+CVE20164979/21223/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_mandatory_keys("apache/http_server/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

vers = infos["version"];
path = infos["location"];

## For when mod_http2 and mod_ssl are enabled --> using qod as remote_banner_unreliable
if(version_in_range(version:vers, test_version:"2.4.18", test_version2:"2.4.20")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.23", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
