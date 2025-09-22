# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108509");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2018-1999043", "CVE-2018-1000406", "CVE-2018-1000407",
                "CVE-2018-1000408", "CVE-2018-1000409", "CVE-2018-1000410", "CVE-2018-1000997");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-12-11 14:42:36 +0100 (Tue, 11 Dec 2018)");

  script_name("Jenkins < 2.146 and < 2.138.2 LTS Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2018-10-10/");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins is prone to the following vulnerabilities:

  - Path traversal vulnerability in Stapler allowed accessing internal data (CVE-2018-1000997).

  - Arbitrary file write vulnerability using file parameter definitions (CVE-2018-1000406).

  - Reflected XSS vulnerability (CVE-2018-1000407).

  - Ephemeral user record was created on some invalid authentication attempts (CVE-2018-1999043).

  - Ephemeral user record creation (CVE-2018-1000408).

  - Session fixation vulnerability on user signup (CVE-2018-1000409).

  - Failures to process form submission data could result in secrets being displayed or written to logs (CVE-2018-1000410).");

  script_tag(name:"affected", value:"Jenkins LTS up to and including 2.138.1, Jenkins weekly up to and including 2.145.");

  script_tag(name:"solution", value:"Upgrade to Jenkins weekly to 2.146 or later / Jenkins LTS to 2.138.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

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
  if ( version_is_less( version:version, test_version:"2.138.2" ) ) {
    fix = "2.138.2";
  }
} else {
  if( version_is_less( version:version, test_version:"2.146" ) ) {
    fix = "2.146";
  }
}

if( fix ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
