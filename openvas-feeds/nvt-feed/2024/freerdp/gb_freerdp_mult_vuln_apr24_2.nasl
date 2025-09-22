# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freerdp_project:freerdp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126728");
  script_version("2025-02-05T05:38:26+0000");
  script_tag(name:"last_modification", value:"2025-02-05 05:38:26 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-04-24 10:00:11 +0000 (Wed, 24 Apr 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-04 17:44:06 +0000 (Tue, 04 Feb 2025)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2024-32658", "CVE-2024-32659", "CVE-2024-32660", "CVE-2024-32661",
                "CVE-2024-32662");

  script_name("FreeRDP < 3.5.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");

  script_tag(name:"summary", value:"FreeRDP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-32658: FreeRDP allows to out-of-bounds read in ExtractRunLengthRegular*.

  - CVE-2024-32659: FreeRDP allows to out-of-bounds read in freerdp_image_copy if
  nWidth is 0 and nHeight is 0.

  - CVE-2024-32660: It is possible for malicious server to crash the FreeRDP client by sending
  invalid huge allocation size.

  - CVE-2024-32661: FreeRDP allows to a possible 'NULL' access and crash in
  rdp_redirection_read_base64_wchar.

  - CVE-2024-32662: FreeRDP allows to out-of-bounds read in ncrush_decompress. This occurs when
  `WCHAR` string is read with twice the size it has and converted to 'UTF-8', 'base64' decoded.
  The string is only used to compare against the redirection server certificate.");

  script_tag(name:"affected", value:"FreeRDP prior to version 3.5.1.");

  script_tag(name:"solution", value:"Update to version 3.5.1 or later.");

  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-vpv3-m3m9-4c2v");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-8jgr-7r33-x87w");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-mxv6-2cw6-m3mx");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-p5m5-342g-pv9m");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-vffh-j6hh-95f4");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"3.5.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"3.5.1", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
