# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807332");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-0788", "CVE-2016-0789", "CVE-2016-0790", "CVE-2016-0791",
                "CVE-2016-0792");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2016-05-20 16:08:55 +0530 (Fri, 20 May 2016)");

  script_name("Jenkins Multiple Vulnerabilities (Feb 2016) - Linux");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The verification of user-provided API tokens with the expected value did
    not use a constant-time comparison algorithm, potentially allowing
    attackers to use statistical methods to determine valid API tokens using
    brute-force methods.

  - The verification of user-provided CSRF crumbs with the expected value did
    not use a constant-time comparison algorithm, potentially allowing attackers
    to use statistical methods to determine valid CSRF crumbs using brute-force
    methods.

  - The Jenkins has several API endpoints that allow low-privilege users to POST
    XML files that then get deserialized by Jenkins. Maliciously crafted XML
    files sent to these API endpoints could result in arbitrary code execution.

  - An HTTP response splitting vulnerability in the CLI command documentation
    allowed attackers to craft Jenkins URLs that serve malicious content.

  - The Jenkins remoting module allowed unauthenticated remote attackers to open
    a JRMP listener on the server hosting the Jenkins master process, which
    allowed arbitrary code execution.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, bypass the protection mechanism,
  gain elevated privileges, bypass intended access restrictions and execute
  arbitrary code.");

  script_tag(name:"affected", value:"Jenkins main line 1.649 and prior, Jenkins LTS 1.642.1 and prior.");

  script_tag(name:"solution", value:"Jenkins main line users should update to 1.650,
  Jenkins LTS users should update to 1.642.2.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2016-02-24/");
  script_xref(name:"URL", value:"https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream");

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
  if( version_is_less( version:version, test_version:"1.642.2" ) ) {
    vuln = TRUE;
    fix = "1.642.2";
  }
} else {
  if( version_is_less( version:version, test_version:"1.650" ) ) {
    vuln = TRUE;
    fix = "1.650";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
