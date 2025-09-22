# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112332");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2018-1999001", "CVE-2018-1999002", "CVE-2018-1999003", "CVE-2018-1999004",
                "CVE-2018-1999005", "CVE-2018-1999006", "CVE-2018-1999007");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-13 19:03:00 +0000 (Mon, 13 Jun 2022)");
  script_tag(name:"creation_date", value:"2018-07-24 10:15:00 +0200 (Tue, 24 Jul 2018)");

  script_name("Jenkins < 2.133 and < 2.121.2 LTS Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2018-07-18/");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins is prone to the following vulnerabilities:

  - Users without Overall/Read permission can have Jenkins reset parts of global configuration on the next restart (CVE-2018-1999001).

  - Arbitrary file read vulnerability (CVE-2018-1999002).

  - Unauthorized users could cancel queued builds (CVE-2018-1999003).

  - Unauthorized users could initiate and abort agent launches (CVE-2018-1999004).

  - Stored XSS vulnerability (CVE-2018-1999005).

  - Unauthorized users are able to determine when a plugin was extracted from its JPI package (CVE-2018-1999006).

  - XSS vulnerability in Stapler debug mode (CVE-2018-1999007).");

  script_tag(name:"affected", value:"Jenkins LTS up to and including 2.121.1, Jenkins weekly up to and including 2.132.");

  script_tag(name:"solution", value:"Upgrade to Jenkins weekly to 2.132 or later / Jenkins LTS to 2.121.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:jenkins:jenkins";

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port:port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if( get_kb_item( "jenkins/" + port + "/is_lts" ) ) {
  if ( version_is_less( version:version, test_version:"2.121.2" ) ) {
    vuln = TRUE;
    fix = "2.121.2";
  }
} else {
  if( version_is_less( version:version, test_version:"2.133" ) ) {
    vuln = TRUE;
    fix = "2.133";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
