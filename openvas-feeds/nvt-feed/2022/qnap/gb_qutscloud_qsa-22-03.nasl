# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qutscloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170120");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2022-05-30 07:54:46 +0000 (Mon, 30 May 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-23 15:47:00 +0000 (Wed, 23 Feb 2022)");

  script_cve_id("CVE-2021-44141", "CVE-2021-44142", "CVE-2022-0336");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTScloud Multiple Samba Vulnerabilities (QSA-22-03)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qutscloud/detected");

  script_tag(name:"summary", value:"QNAP QuTScloud is prone to multiple vulnerabilities in Samba.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2021-44141: Information leak via symlinks of existence of files or directories outside of
  the exported share

  - CVE-2021-44142: Out-of-bounds heap read/write vulnerability in VFS module vfs_fruit allows code
  execution

  - CVE-2022-0336: Samba AD users with permission to write to an account can impersonate arbitrary
  services");

  script_tag(name:"affected", value:"QNAP QuTScloud versions prior to c5.0.1.1949.");

  script_tag(name:"solution", value:"Update to version c5.0.1.1949 build 20220218 or later.

  The following mitigation steps are provided by the vendor:

  - Disable SMB 1

  - Deny guest access to all shared folders");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/QSA-22-03");
  script_xref(name:"URL", value:"https://www.qnap.com/en/release-notes/qutscloud/c5.0.1.1949/20220218");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2021-44141.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2021-44142.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-0336.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

build = get_kb_item( "qnap/nas/qutscloud/build" );

if ( version_is_less( version:version, test_version:"c5.0.1.1949" ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"c5.0.1.1949", fixed_build:"20220218" );
  security_message( port:0, data:report );
  exit( 0 );
}

if ( version_is_equal( version:version, test_version:"c5.0.1.1949" ) &&
   ( ! build || version_is_less( version:build, test_version:"20220218" ) ) ) {
  report = report_fixed_ver( installed_version:version, installed_build:build, fixed_version:"c5.0.1.1949", fixed_build:"20220218" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
