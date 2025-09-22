# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805638");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-3523", "CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-05-27 12:15:46 +0530 (Wed, 27 May 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Only vulnerable if mod_lua/mod_deflate/mod_status/mod_cgid is enabled
  script_name("Apache HTTP Server Multiple Vulnerabilities (May 2015)");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Vulnerability in the WinNT MPM component within the 'winnt_accept' function
  in server/mpm/winnt/child.c script that is triggered when the default
  AcceptFilter is used.

  - Vulnerability in the mod_deflate module that is triggered when handling
  highly compressed bodies.

  - A race condition in the mod_status module that is triggered as user-supplied
  input is not properly validated when handling the scoreboard.

  - Vulnerability in the mod_cgid module that is triggered when used to host CGI
  scripts that do not consume standard input.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to bypass intended access restrictions in opportunistic
  circumstances by leveraging multiple Require directives.");

  script_tag(name:"affected", value:"Apache HTTP Server version before 2.4.10.");

  script_tag(name:"solution", value:"Update to version 2.4.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73040");
  script_xref(name:"URL", value:"http://www.rapid7.com/db/vulnerabilities/apache-httpd-cve-2014-8109");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"2.4.1", test_version2:"2.4.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.10", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);