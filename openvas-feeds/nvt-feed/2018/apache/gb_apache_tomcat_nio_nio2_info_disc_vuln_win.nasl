# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813722");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2018-8037");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-15 16:31:00 +0000 (Mon, 15 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-07-24 11:16:57 +0530 (Tue, 24 Jul 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Tomcat 'NIO/NIO2' Connectors Information Disclosure Vulnerability - Windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error where a
  mishandling of close in 'NIO/NIO2' connectors, user sessions can get mixed up.");

  script_tag(name:"impact", value:"Successful exploitation can allow an attacker
  to reuse user sessions in a new connection.");

  script_tag(name:"affected", value:"Apache Tomcat 9.0.0.M9 to 9.0.9
  Apache Tomcat 8.5.5 to 8.5.31 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apache Tomcat version 9.0.10,
  8.5.32 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://mail-archives.us.apache.org/mod_mbox/www-announce/201807.mbox/%3C20180722090623.GA92700%40minotaur.apache.org%3E");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.10");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.32");

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
  if(version_in_range(version:vers, test_version:"8.5.5", test_version2:"8.5.31")) {
    fix = "8.5.32";
  }
}

else if(vers =~ "^9\.0") {
  if((revcomp(a:vers, b:"9.0.0.M9") >= 0) && (revcomp(a:vers, b:"9.0.10") < 0)) {
    fix = "9.0.10";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
