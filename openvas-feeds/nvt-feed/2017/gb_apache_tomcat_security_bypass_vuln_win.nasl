# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811140");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-5664");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-06-07 15:08:52 +0530 (Wed, 07 Jun 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Tomcat Security Bypass Vulnerability - Windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error page mechanism of the Java Servlet
  Specification requires that, when an error occurs and an error page is
  configured for the error that occurred, the original request and response are
  forwarded to the error page. This means that the request is presented to the
  error page with the original HTTP method. If the error page is a static file,
  expected behaviour is to serve content of the file as if processing a GET request,
  regardless of the actual HTTP method. Tomcat's Default Servlet did not do this.
  Depending on the original request this could lead to unexpected and undesirable
  results for static error pages including, if the DefaultServlet is configured to
  permit writes, the replacement or removal of the custom error page");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  exploit this issue to bypass certain security restrictions and perform
  unauthorized actions. This may lead to further attacks.");

  script_tag(name:"affected", value:"Apache Tomcat 9.0.0.M1 to 9.0.0.M20,
  Apache Tomcat 8.5.0 to 8.5.14,
  Apache Tomcat 8.0.0.RC1 to 8.0.43 and
  Apache Tomcat 7.0.0 to 7.0.77 on Windows");

  script_tag(name:"solution", value:"Upgrade to version 9.0.0.M21, or 8.5.15,
  or 8.0.44, or 7.0.78 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/a42c48e37398d76334e17089e43ccab945238b8b7896538478d76066@%3Cannounce.tomcat.apache.org%3E");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98888");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(tomPort = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:tomPort, exit_no_version:TRUE))
  exit(0);

appVer = infos["version"];
path = infos["location"];

if(appVer =~ "^[7-9]\.")
{
  if(version_in_range(version:appVer, test_version:"8.5.0", test_version2:"8.5.14")){
    fix = "8.5.15";
  }

  else if(version_in_range(version:appVer, test_version:"8.0.0.RC1", test_version2:"8.0.43")){
    fix = "8.0.44";
  }

  else if(version_in_range(version:appVer, test_version:"7.0", test_version2:"7.0.77")){
    fix = "7.0.78";
  }

  else if(version_in_range(version:appVer, test_version:"9.0.0.M1", test_version2:"9.0.0.M20")){
    fix = "9.0.0.M21";
  }

  if(fix)
  {
    report = report_fixed_ver(installed_version:appVer, fixed_version:fix, install_path:path);
    security_message(data:report, port:tomPort);
    exit(0);
  }
}
