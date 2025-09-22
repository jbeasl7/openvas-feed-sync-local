# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1452.1");
  script_cve_id("CVE-2023-39929");
  script_tag(name:"creation_date", value:"2025-05-07 04:07:25 +0000 (Wed, 07 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1452-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1452-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251452-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202828");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224413");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039141.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libva' package(s) announced via the SUSE-SU-2025:1452-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libva fixes the following issues:

Update to libva version 2.20.0, which includes security fix for:

- CVE-2023-39929: Uncontrolled search path may allow an authenticated
 user to escalate privilege via local access (bsc#1224413, jsc#PED-11066)

This includes latest version of one of the components needed for Video (processing) hardware support on Intel GPUs (bsc#1217770)

Update to version 2.20.0:

 * av1: Revise offsets comments for av1 encode
 * drm:
 - Limit the array size to avoid out of range
 - Remove no longer used helpers
 * jpeg: add support for crop and partial decode
 * trace:
 - Add trace for vaExportSurfaceHandle
 - Unlock mutex before return
 - Fix minor issue about printf data type and value range
 * va/backend:
 - Annotate vafool as deprecated
 - Document the vaGetDriver* APIs
 * va/x11/va_fglrx: Remove some dead code
 * va/x11/va_nvctrl: Remove some dead code
 * va:
 - Add new VADecodeErrorType to indicate the reset happended in
 the driver
 - Add vendor string on va_TraceInitialize
 - Added Q416 fourcc (three-plane 16-bit YUV 4:4:4)
 - Drop no longer applicable vaGetDriverNames check
 - Fix:don't leak driver names, when override is set
 - Fix:set driver number to be zero if vaGetDriverNames failed
 - Optimize code of getting driver name for all protocols/os
 (wayland,x11,drm,win32,android)
 - Remove legacy code paths
 - Remove unreachable 'DRIVER BUG'
 * win32:
 - Only print win32 driver messages in DEBUG builds
 - Remove duplicate adapter_luid entry
 * x11/dri2: limit the array handling to avoid out of range access
 * x11:
 - Allow disabling DRI3 via LIBVA_DRI3_DISABLE env var
 - Implement vaGetDriverNames
 - Remove legacy code paths

Update to 2.19.0:

 * add: Add mono_chrome to VAEncSequenceParameterBufferAV1
 * add: Enable support for license acquisition of multiple protected
 playbacks
 * fix: use secure_getenv instead of getenv
 * trace: Improve and add VA trace log for AV1 encode
 * trace: Unify va log message, replace va_TracePrint with va_TraceMsg.

Update to version 2.18.0:

 * doc: Add build and install libva informatio in home page.
 * fix:
 - Add libva.def into distribution package
 - NULL check before calling strncmp.
 - Remove reference to non-existent symbol
 * meson: docs:
 - Add encoder interface for av1
 - Use libva_version over project_version()
 * va:
 - Add VAProfileH264High10
 - Always build with va-messaging API
 - Fix the codying style of CHECK_DISPLAY
 - Remove Android pre Jelly Bean workarounds
 - Remove dummy isValid() hook
 - Remove unused drm_sarea.h include & ANDROID references in
 va_dricommon.h
 - va/sysdeps.h: remove Android section
 * x11:
 - Allow disabling DRI3 via LIBVA_DRI3_DISABLe env var
 - Use LIBVA_DRI3_DISABLE in GetNumCandidates

update to 2.17.0:

 * win: Simplify signature for driver name loading
 * win: Rewrite driver registry query and fix some
 bugs/leaks/inefficiencies
 * win: Add ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libva' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libva-devel", rpm:"libva-devel~2.20.0~150400.3.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libva-drm2", rpm:"libva-drm2~2.20.0~150400.3.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libva-wayland2", rpm:"libva-wayland2~2.20.0~150400.3.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libva-x11-2", rpm:"libva-x11-2~2.20.0~150400.3.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libva2", rpm:"libva2~2.20.0~150400.3.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
