# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808266");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2014-3665");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-05 09:47:29 +0530 (Fri, 05 Aug 2016)");

  script_name("Jenkins Remote Code Execution Vulnerability (Nov 2014) - Linux");

  script_tag(name:"summary", value:"Jenkins is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper verification of
  the shared secret used in JNLP slave connections.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute remote code.");

  script_tag(name:"affected", value:"Jenkins main line prior to 1.587, Jenkins LTS prior to 1.580.1.");

  script_tag(name:"solution", value:"Jenkins main line users should update to 1.587,
  Jenkins LTS users should update to 1.580.1.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2014-10-30/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77573");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_full( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if( get_kb_item( "jenkins/" + port + "/is_lts" ) ) {
  if( version_is_less( version:version, test_version:"1.580.1" ) ) {
    vuln = TRUE;
    fix = "1.580.1";
  }
} else {
  if( version_is_less( version:version, test_version:"1.587" ) ) {
    vuln = TRUE;
    fix = "1.587";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
