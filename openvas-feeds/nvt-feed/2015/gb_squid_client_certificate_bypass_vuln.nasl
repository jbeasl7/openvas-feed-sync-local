# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806104");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-3455");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-08 14:34:34 +0530 (Tue, 08 Sep 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Squid SSL-Bump Certificate Validation Bypass Vulnerability (SQUID-2015:1)");

  script_tag(name:"summary", value:"Squid is prone to certificate validation bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The client-first SSL-bump feature does not
  properly validate X.509 server certificate domain and hostname fields. A remote
  server can create a specially crafted certificate to bypass client certificate
  validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass client certificate validation.");

  script_tag(name:"affected", value:"Squid versions 3.2 through 3.2.13, 3.3 through 3.3.13,
  3.4 through 3.4.12 and 3.5 through 3.5.3.");

  script_tag(name:"solution", value:"Update to version 3.5.4, 3.4.13, 3.3.14, 3.2.14 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1032221");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74438");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2015-0191.html");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2015_1.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers !~ "^3\.[2-5]")
  exit(99);

if(version_in_range(version:vers, test_version:"3.2", test_version2:"3.2.13")) {
  VULN =TRUE;
  Fix = "3.2.14";
}

else if(version_in_range(version:vers, test_version:"3.3", test_version2:"3.3.13")) {
  VULN =TRUE;
  Fix = "3.3.14";
}

else if(version_in_range(version:vers, test_version:"3.4", test_version2:"3.4.12")) {
  VULN =TRUE;
  Fix = "3.4.13";
}

else if(version_in_range(version:vers, test_version:"3.5", test_version2:"3.5.3")) {
  VULN =TRUE;
  Fix = "3.5.4";
}

if(VULN) {
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + Fix + '\n';
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
