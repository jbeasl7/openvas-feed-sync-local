# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freerdp_project:freerdp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133213");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"creation_date", value:"2026-03-31 07:00:11 +0000 (Tue, 31 Mar 2026)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-04-01 20:04:25 +0000 (Wed, 01 Apr 2026)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2026-33952", "CVE-2026-33977", "CVE-2026-33982", "CVE-2026-33983",
                "CVE-2026-33984", "CVE-2026-33985", "CVE-2026-33986", "CVE-2026-33987",
                "CVE-2026-33995");

  script_name("FreeRDP Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("General");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");

  script_tag(name:"summary", value:"FreeRDP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2026-33952: An unvalidated auth_length field read from the network triggers a WINPR_ASSERT()
  failure in rts_read_auth_verifier_no_checks(), causing any FreeRDP client connecting through a
  malicious RDP Gateway to crash with SIGABRT. This is a pre-authentication denial of service
  affecting all FreeRDP clients using RPC-over-HTTP gateway transport. The assertion is active in
  default release builds (WITH_VERBOSE_WINPR_ASSERT=ON).

  - CVE-2026-33977: A malicious RDP server can crash the FreeRDP client by sending audio data in IMA
  ADPCM format with an invalid initial step index value (>= 89). The unvalidated step index is
  read directly from the network and used to index into a 89-entry lookup table, triggering a
  WINPR_ASSERT() failure and process abort via SIGABRT. This affects any FreeRDP client that has
  audio redirection (RDPSND) enabled, which is the default configuration.

  - CVE-2026-33982: A heap-buffer-overflow READ vulnerability at 24 bytes before the allocation, in
  winpr_aligned_offset_recalloc().

  - CVE-2026-33983: progressive_decompress_tile_upgrade() detects a mismatch via
  progressive_rfx_quant_cmp_equal() but only emits WLog_WARN, execution continues. The wrapped value
  (247) is used as a shift exponent, causing undefined behavior and an approximately 80 billion
  iteration loop (CPU DoS).

  - CVE-2026-33984: In resize_vbar_entry() in libfreerdp/codec/clear.c, vBarEntry->size is updated
  to vBarEntry->count before the winpr_aligned_recalloc() call. If realloc fails, size is inflated
  while pixels still points to the old, smaller buffer. On a subsequent call where count <= size
  (the inflated value), realloc is skipped. The caller then writes count * bpp bytes of
  attacker-controlled pixel data into the undersized buffer, causing a heap buffer overflow.

  - CVE-2026-33985: Pixel data from adjacent heap memory is rendered to screen, potentially leaking
  sensitive data to the attacker.

  - CVE-2026-33986: In yuv_ensure_buffer() in libfreerdp/codec/h264.c, h264->width and h264->height
  are updated before the reallocation loop. If any winpr_aligned_recalloc() call fails, the function
  returns FALSE but width/height are already inflated.

  - CVE-2026-33987: In persistent_cache_read_entry_v3() in libfreerdp/cache/persistent.c,
  persistent->bmpSize is updated before winpr_aligned_recalloc(). If realloc fails, bmpSize is
  inflated while bmpData points to the old buffer.

  - CVE-2026-33995: A double-free vulnerability in kerberos_AcceptSecurityContext() and
  kerberos_InitializeSecurityContextA() (WinPR, winpr/libwinpr/sspi/Kerberos/kerberos.c) can cause
  a crash in any FreeRDP clients on systems where Kerberos and/or Kerberos U2U is configured (Samba
  AD member, or krb5 for NFS). The crash is triggered during NLA connection teardown and requires a
  failed authentication attempt.");

  script_tag(name:"affected", value:"FreeRDP prior to version 3.24.2.");

  script_tag(name:"solution", value:"Update to version 3.24.2 or later.");

  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-4v4p-9v5x-hc93");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-8f2g-3q27-6xm5");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-8jm9-2925-g4v2");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-4gfm-4p52-h478");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-8469-2xcx-frf6");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-x6gr-8p7h-5h85");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-h6qw-wxvm-hf97");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-ff8h-p5vc-wcwc");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-mv25-f4p2-5mxx");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"3.24.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"3.24.2", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
