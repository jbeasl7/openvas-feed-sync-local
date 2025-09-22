# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108062");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2016-9299");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-22 15:06:00 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2017-01-30 13:00:00 +0100 (Mon, 30 Jan 2017)");

  script_name("Jenkins 'Java Deserialization' Remote Code Execution Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2016-11-16/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94281");

  script_tag(name:"summary", value:"Jenkins is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an Jenkins allowing to transfer a serialized Java object to the Jenkins CLI,
  making Jenkins connect to an attacker-controlled LDAP server, which in turn can send a serialized payload leading
  to code execution, bypassing existing protection mechanisms.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to execute arbitrary code in the context of
  the affected application. Failed exploits will result in denial-of-service conditions.");

  script_tag(name:"affected", value:"Jenkins LTS 2.19.2 and prior, Jenkins 2.31 and prior.");

  script_tag(name:"solution", value:"Upgrade to Jenkins to 2.32 or later / Jenkins LTS to 2.19.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
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
  if( version_is_less( version:version, test_version:"2.19.3" ) ) {
    vuln = TRUE;
    fix = "2.19.3";
  }
} else {
  if( version_is_less( version:version, test_version:"2.32" ) ) {
    vuln = TRUE;
    fix = "2.32";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
