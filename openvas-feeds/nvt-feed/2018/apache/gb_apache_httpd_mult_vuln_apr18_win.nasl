# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812846");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2018-1312", "CVE-2018-1283", "CVE-2017-15715", "CVE-2017-15710",
                "CVE-2018-1301");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 17:45:00 +0000 (Wed, 07 Sep 2022)");
  script_tag(name:"creation_date", value:"2018-04-04 15:09:39 +0530 (Wed, 04 Apr 2018)");
  script_name("Apache HTTP Server Multiple Vulnerabilities (Apr 2018) - Windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Apache HTTP Server fails to correctly generate the nonce sent to prevent
    reply attacks.

  - Misconfigured mod_session variable, HTTP_SESSION.

  - Apache HTTP Server fails to sanitize the expression specified in '<FilesMatch>'.

  - An error in Apache HTTP Server 'mod_authnz_ldap' when configured with
    AuthLDAPCharsetConfig.

  - Apache HTTP Server fails to sanitize against a specially crafted request.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to replay HTTP requests across servers without detection, influence the user
  content, upload a malicious file, crash the Apache HTTP Server and perform
  denial of service attack.");

  script_tag(name:"affected", value:"Apache HTTP Server versions from 2.4.1 to
  2.4.4, 2.4.6, 2.4.7, 2.4.9, 2.4.10, 2.4.12, 2.4.16 to 2.4.18, 2.4.20, 2.4.23,
  2.4.25 to 2.4.29.");

  script_tag(name:"solution", value:"Update to version 2.4.30 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103524");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103520");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103525");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103512");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103515");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_windows");

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

not_affected = make_list("2.4.5", "2.4.8", "2.4.11", "2.4.13", "2.4.14", "2.4.15", "2.4.19", "2.4.21", "2.4.22", "2.4.24");

if(version_in_range(version:vers, test_version:"2.4.1", test_version2:"2.4.29")) {
  foreach version(not_affected) {
    if(vers == version)
      exit(99);
  }

  report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.30", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
