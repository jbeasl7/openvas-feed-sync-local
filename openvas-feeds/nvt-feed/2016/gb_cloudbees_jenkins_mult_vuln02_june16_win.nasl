# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807344");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2015-1812", "CVE-2015-1813", "CVE-2015-1814");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-22 14:22:34 +0530 (Wed, 22 Jun 2016)");

  script_name("Jenkins Multiple Vulnerabilities (Mar 2015) - Windows");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The part of Jenkins that issues a new API token was not adequately protected
    against anonymous attackers. This allows an attacker to escalate privileges
    on Jenkins.

  - A without any access to Jenkins can navigate the user to a carefully crafted
    URL and have the user execute unintended actions. This vulnerability can be
    used to attack Jenkins inside firewalls from outside so long as the location
    of Jenkins is known to the attacker.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, bypass the protection mechanism,
  gain elevated privileges, bypass intended access restrictions and execute
  arbitrary code.");

  script_tag(name:"affected", value:"Jenkins main line 1.605 and prior, Jenkins LTS 1.596.1 and prior.");

  script_tag(name:"solution", value:"Jenkins main line users should update to 1.606,
  Jenkins LTS users should update to 1.596.2.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205616");
  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2015-03-23/");

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
  if( version_is_less( version:version, test_version:"1.596.2" ) ) {
    vuln = TRUE;
    fix = "1.596.2";
  }
} else {
  if( version_is_less( version:version, test_version:"1.606" ) ) {
    vuln = TRUE;
    fix = "1.606";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
