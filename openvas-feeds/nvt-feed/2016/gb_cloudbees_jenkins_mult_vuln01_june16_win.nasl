# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807342");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2015-1806", "CVE-2015-1807", "CVE-2015-1808", "CVE-2015-18010");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-22 14:13:22 +0530 (Wed, 22 Jun 2016)");

  script_name("Jenkins Multiple Vulnerabilities (Feb 2015) - Windows");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The job configuration privilege to escalate his privileges, resulting in
    arbitrary code execution to the master.

  - The build script to access arbitrary files/directories on the master, resulting
    in the exposure of sensitive information, such as encryption keys.

  - The operation of Jenkins by feeding malicious update center data into Jenkins,
    affecting plugin installation and tool installation.

  - The read access to Jenkins to retrieve arbitrary XML document on the server,
    resulting in the exposure of sensitive information inside/outside Jenkins.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, bypass the protection mechanism,
  gain elevated privileges, bypass intended access restrictions and execute arbitrary code.");

  script_tag(name:"affected", value:"Jenkins main line prior to 1.600, Jenkins LTS 1.580.3 and prior.");

  script_tag(name:"solution", value:"Main line users should upgrade to Jenkins 1.600,
  LTS users should upgrade to 1.596.1.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205620");
  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2015-02-27/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

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
  if( version_is_less( version:version, test_version:"1.596.1" ) ) {
    vuln = TRUE;
    fix = "1.596.1";
  }
} else {
  if( version_is_less( version:version, test_version:"1.600" ) ) {
    vuln = TRUE;
    fix = "1.600";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
