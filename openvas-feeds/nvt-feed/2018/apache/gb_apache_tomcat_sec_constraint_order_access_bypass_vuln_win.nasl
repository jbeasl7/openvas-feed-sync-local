# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812784");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2018-1305", "CVE-2018-1304");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-02-26 18:10:55 +0530 (Mon, 26 Feb 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Tomcat Security Constraint Incorrect Handling Access Bypass Vulnerabilities - Windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to multiple access bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The system does not properly enforce security constraints that defined by
    annotations of Servlets in certain cases, depending on the order that Servlets
    are loaded.

  - The URL pattern of '' (the empty string) which exactly maps to the context
    root was not correctly handled when used as part of a security constraint
    definition.");

  script_tag(name:"impact", value:"Successfully exploiting these issues will allow
  remote attackers to bypass security constraints to access ostensibly restricted
  resources on the target system.");

  script_tag(name:"affected", value:"Apache Tomcat versions 9.0.0.M1 to 9.0.4

  Apache Tomcat versions 8.5.0 to 8.5.27

  Apache Tomcat versions 8.0.0.RC1 to 8.0.49

  Apache Tomcat versions 7.0.0 to 7.0.84 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apache Tomcat version 9.0.5,
  8.5.28, 8.0.50, 7.0.85 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103144");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103170");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/b1d7e2425d6fd2cebed40d318f9365b44546077e10949b01b1f8a0fb@%3Cannounce.tomcat.apache.org%3E");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^8\.5") {
  if(version_in_range(version:vers, test_version:"8.5.0", test_version2:"8.5.27")) {
    fix = "8.5.28";
  }
}

else if(vers =~ "^7\.0") {
  if(version_in_range(version:vers, test_version:"7.0.0", test_version2:"7.0.84")) {
    fix = "7.0.85";
  }
}

else if(vers =~ "^8\.0") {
  if((revcomp(a:vers, b:"8.0.0.RC1") >= 0) && (revcomp(a:vers, b:"8.0.50") < 0)) {
    fix = "8.0.50";
  }
}

else if(vers =~ "^9\.0") {
  if((revcomp(a:vers, b:"9.0.0.M1") >= 0) && (revcomp(a:vers, b:"9.0.5") < 0)) {
    fix = "9.0.5";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
