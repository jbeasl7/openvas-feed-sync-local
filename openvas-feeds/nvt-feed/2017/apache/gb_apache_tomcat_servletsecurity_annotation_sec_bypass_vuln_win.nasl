# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812241");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2011-1088", "CVE-2011-1419");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-12-12 11:08:44 +0530 (Tue, 12 Dec 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Tomcat 'ServletSecurity' Annotations Security Bypass Vulnerability - Windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to when a web application
  was started, ServletSecurity annotations were ignored. This meant that some
  areas of the application may not have been protected as expected.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass certain authentication and obtain sensitive information.");

  script_tag(name:"affected", value:"Apache Tomcat versions 7.0.0 to 7.0.10
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Tomcat version 7.0.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.11");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46685");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/517013/100/0/threaded");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

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

if(vers =~ "^7\.") {
  if(version_is_less(version:vers, test_version:"7.0.11")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"7.0.11", install_path:path);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
