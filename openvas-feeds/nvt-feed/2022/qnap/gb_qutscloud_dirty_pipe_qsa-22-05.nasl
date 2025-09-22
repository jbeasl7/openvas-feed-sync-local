# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qutscloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170122");
  script_version("2024-07-05T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-05 05:05:40 +0000 (Fri, 05 Jul 2024)");
  script_tag(name:"creation_date", value:"2022-05-30 09:20:47 +0000 (Mon, 30 May 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 19:07:00 +0000 (Thu, 10 Mar 2022)");

  script_cve_id("CVE-2022-0847");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTScloud Privilege Escalation Vulnerability (QSA-22-05)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qutscloud/detected");

  script_tag(name:"summary", value:"QNAP QuTScloud is prone to a local privilege escalation
  vulnerability, also known as dirty pipe.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If exploited, this vulnerability allows an unprivileged user to
  gain administrator privileges and inject malicious code.");

  script_tag(name:"affected", value:"QNAP QuTScloud version c5.x prior to c5.0.0.1998 build
  20220408.");

  script_tag(name:"solution", value:"Update to version c5.0.0 build 20220408.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-22-05");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/166229/Dirty-Pipe-Linux-Privilege-Escalation.html");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

build = get_kb_item( "qnap/nas/qutscloud/build" );

if ( version_in_range_exclusive( version:version, test_version_lo:"c5.0.0", test_version_up:"c5.0.0.1998" ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"c5.0.0.1998", fixed_build:"20220408" );
  security_message( port:0, data:report );
  exit( 0 );
}

if ( version_is_equal( version:version, test_version:"c5.0.0.1998" ) &&
   ( ! build || version_is_less( version:build, test_version:"20220408" ) ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"c5.0.0.1998", fixed_build:"20220408" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
