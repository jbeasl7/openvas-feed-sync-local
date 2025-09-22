# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:h2o_project:h2o";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806994");
  script_version("2024-06-11T05:05:40+0000");
  script_cve_id("CVE-2016-1133");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-19 14:01:00 +0000 (Mon, 19 Apr 2021)");
  script_tag(name:"creation_date", value:"2016-01-25 15:37:05 +0530 (Mon, 25 Jan 2016)");
  script_name("H2O HTTP Server < 1.6.2, 1.7.x < 1.7.0-beta3 CRLF Injection Vulnerability");

  script_tag(name:"summary", value:"H2O HTTP Server is prone to CRLF Injection Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation
  of user supplied input by 'on_req function' in 'lib/handler/redirect.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to inject arbitrary HTTP headers and conduct HTTP response
  splitting attacks.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"affected", value:"H2O HTTP Server versions before 1.6.2 and
  1.7.x before 1.7.0-beta3.");

  script_tag(name:"solution", value:"Upgrade to version 1.6.2 or 1.7.0-beta3
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2016/JVNDB-2016-000003.html");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_h2o_http_server_http_detect.nasl");
  script_mandatory_keys("h2o/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
 exit(0);

if (!version = get_app_version(cpe:CPE, port:port))
 exit(0);

# nb: some versions contains '-' in version
version = ereg_replace(string:version, pattern:"-", replace:".");

if(version_is_less(version:version, test_version:"1.6.2")) {
  fix = "1.6.2";
  VULN = TRUE;
}

else if(version_in_range(version:version, test_version:"1.7.0", test_version2:"1.7.0.beta2")) {
  fix = "1.7.0-beta3";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
