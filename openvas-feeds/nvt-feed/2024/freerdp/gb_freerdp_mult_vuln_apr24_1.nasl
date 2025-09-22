# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freerdp_project:freerdp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126713");
  script_version("2025-02-05T05:38:26+0000");
  script_tag(name:"last_modification", value:"2025-02-05 05:38:26 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-04-23 14:00:11 +0000 (Tue, 23 Apr 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-04 17:58:52 +0000 (Tue, 04 Feb 2025)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2024-32039", "CVE-2024-32040", "CVE-2024-32041", "CVE-2024-32458",
                "CVE-2024-32459", "CVE-2024-32460");

  script_name("FreeRDP < 2.11.6, 3.x < 3.5.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");

  script_tag(name:"summary", value:"FreeRDP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-32039: FreeRDP allows to integer overflow and out-of-bounds write in
  clear_decompress_residual_data.

  Note: As a workaround, do not use `/gfx` options (e.g. deactivate with `/bpp:32` or `/rfx` as it
  is on by default).

  - CVE-2024-32040: FreeRDP that have connections to servers using the `NSC` codec allows to
  integer underflow in nsc_rle_decode.

  Note: As a workaround, do not use the NSC codec (e.g. use `-nsc`).

  - CVE-2024-32041: FreeRDP allows to out-of-bounds read in zgfx_decompress_segment.

  Note: As a workaround, deactivate `/gfx` (on by default, set `/bpp` or `/rfx` options instead.

  - CVE-2024-32458: FreeRDP allows to out-of-bounds read in planar_skip_plane_rle.

  Note: As a workaround, use `/gfx` or `/rfx` modes (on by default, require server side support).

  - CVE-2024-32459: FreeRDP allows to out-of-bounds read in ncrush_decompress.

  - CVE-2024-32460: FreeRDP allows to out-of-bounds read in interleaved_decompress.

  Note: As a workaround, use modern drawing paths (e.g. `/rfx` or `/gfx` options). The workaround
  requires server side support.");

  script_tag(name:"affected", value:"FreeRDP prior to version 2.11.6 and 3.x prior to 3.5.0.");

  script_tag(name:"solution", value:"Update to version 2.11.6, 3.5.0 or later.");

  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-q5h8-7j42-j4r9");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-23c5-cp23-h2h5");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-5r4p-mfx2-m44r");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-vvr6-h646-mp4p");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-cp4q-p737-rmw9");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-4rr8-gr65-vqrr");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"2.11.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"2.11.6", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"3.0", test_version_up:"3.5.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.5.0", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
