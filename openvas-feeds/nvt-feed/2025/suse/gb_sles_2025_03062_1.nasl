# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03062.1");
  script_cve_id("CVE-2025-23277", "CVE-2025-23278", "CVE-2025-23279", "CVE-2025-23283", "CVE-2025-23286");
  script_tag(name:"creation_date", value:"2025-09-05 04:12:36 +0000 (Fri, 05 Sep 2025)");
  script_version("2025-09-05T05:38:20+0000");
  script_tag(name:"last_modification", value:"2025-09-05 05:38:20 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03062-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03062-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503062-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247532");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041504.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia-open-driver-G06-signed' package(s) announced via the SUSE-SU-2025:03062-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nvidia-open-driver-G06-signed fixes the following issues:

Updated CUDA variant to 580.65.06:

- CVE-2025-23277: Fixed access memory outside bounds permitted under normal
 use cases in NVIDIA Display Driver (bsc#1247528)
- CVE-2025-23278: Fixed improper index validation by issuing a call with
 crafted parameters in NVIDIA Display Driver (bsc#1247529)
- CVE-2025-23286: Fixed invalid memory read in NVIDIA GPU Display Driver (bsc#1247530)
- CVE-2025-23283: Fixed stack buffer overflow triggerable by a malicious guest
 in Virtual GPU Manager in NVIDIA vGPU software (bsc#1247531)
- CVE-2025-23279: Fixed race condition that lead to privileges escalations
 in NVIDIA .run Installer (bsc#1247532)


Updated non-CUDA variant to 570.172.08 (bsc#1246327)");

  script_tag(name:"affected", value:"'nvidia-open-driver-G06-signed' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"nv-prefer-signed-open-driver", rpm:"nv-prefer-signed-open-driver~580.65.06~150500.3.73.7", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-64kb-devel", rpm:"nvidia-open-driver-G06-signed-64kb-devel~570.172.08~150500.3.73.7", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-64kb-devel", rpm:"nvidia-open-driver-G06-signed-cuda-64kb-devel~580.65.06~150500.3.73.7", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-default-devel", rpm:"nvidia-open-driver-G06-signed-cuda-default-devel~580.65.06~150500.3.73.7", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-64kb~580.65.06_k5.14.21_150500.55.116~150500.3.73.7", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-default", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-default~580.65.06_k5.14.21_150500.55.116~150500.3.73.7", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-default-devel", rpm:"nvidia-open-driver-G06-signed-default-devel~570.172.08~150500.3.73.7", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-kmp-64kb~570.172.08_k5.14.21_150500.55.116~150500.3.73.7", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default", rpm:"nvidia-open-driver-G06-signed-kmp-default~570.172.08_k5.14.21_150500.55.116~150500.3.73.7", rls:"SLES15.0SP5"))) {
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
