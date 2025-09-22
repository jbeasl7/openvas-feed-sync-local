# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812695");
  script_version("2024-10-23T05:05:59+0000");
  script_cve_id("CVE-2017-15706");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-15 16:31:00 +0000 (Mon, 15 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-02-06 12:00:53 +0530 (Tue, 06 Feb 2018)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Incorrectly Documented CGI Search Algorithm (Jan 2018) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat has an incorrectly documented CGI search
  algorithm.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the description of the search algorithm used
  by the CGI Servlet to identify which script to execute was not correct.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will result some scripts
  failing to execute as expected and other scripts to execute unexpectedly.");

  script_tag(name:"affected", value:"Apache Tomcat versions 7.0.79 through 7.0.82, 8.0.45 through
  8.0.47, 8.5.16 through 8.5.23 and 9.0.0.M22 through 9.0.1.");

  script_tag(name:"solution", value:"Update to version 7.0.84, 8.0.48, 8.5.24, 9.0.2 or later.");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/jocvjoxftkq59c4z8sdp12oskkvm56dy");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version =~ "^8\.5") {
  if(version_in_range(version:version, test_version:"8.5.16", test_version2:"8.5.23")) {
    fix = "8.5.24";
  }
}

else if(version =~ "^7\.0") {
  if(version_in_range(version:version, test_version:"7.0.79", test_version2:"7.0.82")) {
    fix = "7.0.84";
  }
}

else if(version =~ "^8\.0") {
  if(version_in_range(version:version, test_version:"8.0.45", test_version2:"8.0.47")) {
    fix = "8.0.48";
  }
}

else if(version =~ "^9\.0") {
  if((revcomp(a:version, b:"9.0.0.M22") >= 0) && (revcomp(a:version, b:"9.0.2") < 0)) {
    fix = "9.0.2";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
