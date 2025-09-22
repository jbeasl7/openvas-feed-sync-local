# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900842");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_cve_id("CVE-2009-3095");
  script_name("Apache HTTP Server 'mod_proxy_ftp' Module Command Injection Vulnerability");
  script_xref(name:"URL", value:"http://intevydis.com/vd-list.shtml");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36254");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_22.html");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_20.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_mandatory_keys("apache/http_server/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to
  bypass intended access restrictions in the context of the affected application, and can
  cause the arbitrary command injection.");

  script_tag(name:"affected", value:"Apache HTTP Server 1.3.x, 2.0.x through 2.0.63 and 2.2.x through 2.2.13
  running mod_proxy_ftp.");

  script_tag(name:"insight", value:"The flaw is due to error in the mod_proxy_ftp module which
  can be exploited via vectors related to the embedding of these commands in the Authorization
  HTTP header.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to Apache HTTP Server version 2.0.64, 2.2.14
  or later.");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a command injection
  vulnerability.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"1.3.41") ||
   version_in_range(version:vers, test_version:"2.0", test_version2:"2.0.63") ||
   version_in_range(version:vers, test_version:"2.2", test_version2:"2.2.13")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.0.64 / 2.2.14", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
