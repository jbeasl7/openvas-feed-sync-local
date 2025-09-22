# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03247.1");
  script_cve_id("CVE-2025-23277", "CVE-2025-23278", "CVE-2025-23279", "CVE-2025-23283", "CVE-2025-23286");
  script_tag(name:"creation_date", value:"2025-09-19 04:06:37 +0000 (Fri, 19 Sep 2025)");
  script_version("2025-09-19T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03247-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03247-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503247-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249235");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041721.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia-open-driver-G06-signed' package(s) announced via the SUSE-SU-2025:03247-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nvidia-open-driver-G06-signed fixes the following issues:

Updated CUDA variant to 580.82.07:

- CVE-2025-23277: Fixed access memory outside bounds permitted under normal
 use cases in NVIDIA Display Driver (bsc#1247528).
- CVE-2025-23278: Fixed improper index validation by issuing a call with
 crafted parameters in NVIDIA Display Driver (bsc#1247529).
- CVE-2025-23286: Fixed invalid memory read in NVIDIA GPU Display Driver (bsc#1247530).
- CVE-2025-23283: Fixed stack buffer overflow triggerable by a malicious guest
 in Virtual GPU Manager in NVIDIA vGPU software (bsc#1247531).
- CVE-2025-23279: Fixed race condition that lead to privileges escalations
 in NVIDIA .run Installer (bsc#1247532).

Update non-CUDA variant to 580.82.07 (bsc#1249235).

Other fixes:

- Added Requires to be provided by special versions of nvidia-modprobe and
 nvidia-persitenced built against SP4 (bsc#1237208, jsc#PED-13295).
- Get rid of rule of older KMPs not to load nvidia_drm module,
 which are still installed in parallel and therefore still
 active (bsc#1247923).");

  script_tag(name:"affected", value:"'nvidia-open-driver-G06-signed' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"nv-prefer-signed-open-driver", rpm:"nv-prefer-signed-open-driver~580.82.07~150600.3.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-64kb-devel", rpm:"nvidia-open-driver-G06-signed-64kb-devel~580.82.07~150600.3.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-azure-devel", rpm:"nvidia-open-driver-G06-signed-azure-devel~580.82.07~150600.3.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-64kb-devel", rpm:"nvidia-open-driver-G06-signed-cuda-64kb-devel~580.82.07~150600.3.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-azure-devel", rpm:"nvidia-open-driver-G06-signed-cuda-azure-devel~580.82.07~150600.3.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-default-devel", rpm:"nvidia-open-driver-G06-signed-cuda-default-devel~580.82.07~150600.3.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-64kb~580.82.07_k6.4.0_150600.23.65~150600.3.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-azure", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-azure~580.82.07_k6.4.0_150600.8.48~150600.3.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-default", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-default~580.82.07_k6.4.0_150600.23.65~150600.3.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-default-devel", rpm:"nvidia-open-driver-G06-signed-default-devel~580.82.07~150600.3.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-kmp-64kb~580.82.07_k6.4.0_150600.23.65~150600.3.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-azure", rpm:"nvidia-open-driver-G06-signed-kmp-azure~580.82.07_k6.4.0_150600.8.48~150600.3.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default", rpm:"nvidia-open-driver-G06-signed-kmp-default~580.82.07_k6.4.0_150600.23.65~150600.3.63.1", rls:"openSUSELeap15.6"))) {
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
