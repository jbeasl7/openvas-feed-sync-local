# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140172");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2017-02-22 13:24:30 +0100 (Wed, 22 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS < 4.2.3 build 20170213 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"QNAP QTS software firmware update functionality include Missing
  transport layer security (CWE-319), command injection (CWE-77) and cross-site scripting (CWE-79)
  vulnerabilities.

  QNAP QTS myQNAPcloud functionality includes improper certificate validation (CWE-295) vulnerability.

  QNAP QTS media scraping functionality automatically scrapes Google and IMDB for media information
  (for example album cover images). The functionality contains an Information Exposure (CWE-200)
  vulnerability.");

  script_tag(name:"impact", value:"An attacker in a privileged network position can Man-in-The-Middle
  the firmware update check and exploit the command injection vulnerability to execute arbitrary
  commands on the targeted device, eavesdrop the myQNAPcloud credentials and the requests performed.");

  script_tag(name:"affected", value:"QNAP QTS < 4.2.3 build 20170213");

  script_tag(name:"solution", value:"Update to QNAP QTS 4.2.3 build 20170213 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/de-de/releasenotes/");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/141123/QNAP-QTS-4.2.x-XSS-Command-Injection-Transport-Issues.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

build = get_kb_item( "qnap/nas/qts/build" );

if( version_is_less( version:version, test_version:"4.2.3" ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"4.2.3", fixed_build:"20170213" );
  security_message( port:0, data:report );
  exit( 0 );
} else if( version_is_equal( version:version, test_version:"4.2.3" ) &&
          ( ! build || version_is_less( version:build, test_version:"20170213" ) ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"4.2.3", fixed_build:"20170213" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
