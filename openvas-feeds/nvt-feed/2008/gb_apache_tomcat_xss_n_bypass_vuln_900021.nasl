# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900021");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-07 17:25:16 +0200 (Thu, 07 Aug 2008)");
  script_cve_id("CVE-2008-1232", "CVE-2008-2370");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_name("Apache Tomcat Multiple Vulnerabilities (Jul/Sep 2008)");

  script_xref(name:"URL", value:"https://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.18");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.27");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-4.html#Fixed_in_Apache_Tomcat_4.1.39");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31379/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30494");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30496");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31381/");

  script_tag(name:"summary", value:"Apache Tomcat is prone to cross-site scripting (XSS) and
  security bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to:

  - CVE-2008-1232: Input validation error in the method HttpServletResponse.sendError() which fails
  to properly
  sanitise before being returned to the user in the HTTP Reason-Phrase

  - CVE-2008-2370: The application fails to normalize the target path before removing the query
  string when using a RequestDispatcher");

  script_tag(name:"impact", value:"Successful exploitation could cause execution of arbitrary
  HTML code, script code, and information disclosure.");

  script_tag(name:"affected", value:"Apache Tomcat versions 4.1.37 and prior, 5.5.x through 5.5.26
  and 6.0.0 through 6.0.16.");

  script_tag(name:"solution", value:"Update to version 4.1.39, 5.5.27, 6.0.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"4.1.37")) {
  fix = "4.1.38";
  VULN = TRUE;
}

else if(vers =~ "^5\.5") {
  if(version_in_range(version:vers, test_version:"5.5.0", test_version2:"5.5.26")) {
    fix = "5.5.27";
    VULN = TRUE;
  }
}

else if(vers =~ "^6\.0") {
  if(version_in_range(version:vers, test_version:"6.0.0", test_version2:"6.0.16")) {
    fix = "6.0.17";
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
