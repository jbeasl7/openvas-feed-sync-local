# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112495");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2019-1003003", "CVE-2019-1003004");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-02 20:15:00 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"creation_date", value:"2019-01-23 10:08:11 +0100 (Wed, 23 Jan 2019)");

  script_name("Jenkins < 2.160 and < 2.150.2 LTS Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Jenkins and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins is prone to the following vulnerabilities:

  - Administrators could persist access to Jenkins using crafted 'Remember me' cookie (CVE-2019-1003003).

  - Deleting a user in an external security realm did not invalidate their session or 'Remember me' cookie (CVE-2019-1003004).");

  script_tag(name:"affected", value:"Jenkins LTS through 2.150.1, Jenkins weekly through 2.159.");

  script_tag(name:"solution", value:"Upgrade Jenkins weekly to 2.160 or later / Jenkins LTS to 2.150.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2019-01-16/");

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
  if ( version_is_less( version:version, test_version:"2.150.2" ) ) {
    fix = "2.150.2";
  }
} else {
  if( version_is_less( version:version, test_version:"2.160" ) ) {
    fix = "2.160";
  }
}

if( fix ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
