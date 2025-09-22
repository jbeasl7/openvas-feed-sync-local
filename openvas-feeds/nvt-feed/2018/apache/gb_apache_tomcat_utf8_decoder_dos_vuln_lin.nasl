# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813725");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2018-1336");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-15 21:15:00 +0000 (Wed, 15 Apr 2020)");
  script_tag(name:"creation_date", value:"2018-07-24 13:21:03 +0530 (Tue, 24 Jul 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Tomcat 'UTF-8 Decoder' Denial of Service Vulnerability - Linux");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper handing
  of overflow in the UTF-8 decoder with supplementary characters.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct a denial-of-service condition.");

  script_tag(name:"affected", value:"Apache Tomcat 9.0.0.M9 to 9.0.7
  Apache Tomcat 8.5.0 to 8.5.30
  Apache Tomcat 8.0.0.RC1 to 8.0.51
  Apache Tomcat 7.0.28 to 7.0.86 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Apache Tomcat version 9.0.8 or
  8.5.31 or 8.0.52 or 7.0.90 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://mail-archives.us.apache.org/mod_mbox/www-announce/201807.mbox/%3C20180722090435.GA60759%40minotaur.apache.org%3E");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.8");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.31");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.52");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

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
  if(version_in_range(version:vers, test_version:"8.5.0", test_version2:"8.5.30")) {
    fix = "8.5.31";
  }
}

else if(vers =~ "^7\.0") {
  if(version_in_range(version:vers, test_version:"7.0.28", test_version2:"7.0.86")) {
    fix = "7.0.90";
  }
}

else if(vers =~ "^8\.0") {
  if((revcomp(a:vers, b:"8.0.0.RC1") >= 0) && (revcomp(a:vers, b:"8.0.52") < 0)) {
    fix = "8.0.52";
  }
}

else if(vers =~ "^9\.0") {
  if((revcomp(a:vers, b:"9.0.0.M9") >= 0) && (revcomp(a:vers, b:"9.0.8") < 0)) {
    fix = "9.0.8";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
