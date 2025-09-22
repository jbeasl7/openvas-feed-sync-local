# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qutscloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170127");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2022-05-27 19:20:06 +0000 (Fri, 27 May 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-14 19:57:00 +0000 (Fri, 14 Jan 2022)");

  script_cve_id("CVE-2021-38674");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTScloud XSS Vulnerability (QSA-21-63)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qutscloud/detected");

  script_tag(name:"summary", value:"QNAP QuTScloud is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A reflected cross-site scripting (XSS) vulnerability has been
  reported to affect TFTP Server in QuTScloud.");

  script_tag(name:"impact", value:"If exploited, this vulnerability allows remote attackers to
  inject malicious code.");

  script_tag(name:"solution", value:"Update to version c4.5.7 build 20211126 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-21-63");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

build = get_kb_item( "qnap/nas/qutscloud/build" );

if ( version_is_less( version:version, test_version:"c4.5.7.1864" ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"c4.5.7.1864", fixed_build:"20211126" );
  security_message( port:0, data:report );
  exit( 0 );
}

if ( version_is_equal( version:version, test_version:"c4.5.7.1864" ) &&
   ( ! build || version_is_less( version:build, test_version:"20211126" ) ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"c4.5.7.1864", fixed_build:"20211126" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
