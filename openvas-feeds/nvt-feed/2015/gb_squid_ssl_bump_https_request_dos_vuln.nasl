# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806107");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2014-0128");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-08 16:31:16 +0530 (Tue, 08 Sep 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Squid SSL-Bump HTTPS Requests Processing DoS Vulnerability (SQUID-2014:1)");

  script_tag(name:"summary", value:"Squid is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to incorrect state management Squid is vulnerable to a
  denial of service attack when processing certain HTTPS requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial of service.");

  script_tag(name:"affected", value:"Squid versions 3.1 through 3.3.11 and 3.4 through
  3.4.3.");

  script_tag(name:"solution", value:"Apply the patch or update to version 3.4.4, 3.3.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2014_1.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66112");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Denial of Service");
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

if(vers !~ "^3\.")
  exit(99);

if(version_in_range(version:vers, test_version:"3.1", test_version2:"3.3.11")) {
  VULN = TRUE;
  Fix = "3.3.12";
}

else if(version_in_range(version:vers, test_version:"3.4", test_version2:"3.4.3")) {
  VULN =TRUE;
  Fix = "3.4.4";
}

if(VULN) {
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + Fix + '\n';
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
