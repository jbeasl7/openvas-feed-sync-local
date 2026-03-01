# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0456.1");
  script_tag(name:"creation_date", value:"2026-02-16 04:44:21 +0000 (Mon, 16 Feb 2026)");
  script_version("2026-02-16T06:02:08+0000");
  script_tag(name:"last_modification", value:"2026-02-16 06:02:08 +0000 (Mon, 16 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0456-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0456-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260456-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255858");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024135.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia-modprobe.cuda, nvidia-open-driver-G06-signed, nvidia-persistenced.cuda' package(s) announced via the SUSE-SU-2026:0456-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nvidia-modprobe.cuda, nvidia-open-driver-G06-signed, nvidia-persistenced.cuda fixes the following issues:

Changes in nvidia-open-driver-G06-signed:

- updated CUDA variant to version 580.126.09
- update non-CUDA variant to version 580.126.09 (bsc#1255858)
- update non-CUDA variant to version 580.119.02 (bsc#1254801)

Changes in nvidia-persistenced.cuda:

- update to version 580.126.09

Changes in nvidia-modprobe.cuda:

- update to version 580.126.09");

  script_tag(name:"affected", value:"'nvidia-modprobe.cuda, nvidia-open-driver-G06-signed, nvidia-persistenced.cuda' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"nv-prefer-signed-open-driver", rpm:"nv-prefer-signed-open-driver~580.126.09~150500.3.85.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-modprobe", rpm:"nvidia-modprobe~580.126.09~150500.12.6.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-64kb-devel", rpm:"nvidia-open-driver-G06-signed-64kb-devel~580.126.09~150500.3.85.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-64kb-devel", rpm:"nvidia-open-driver-G06-signed-cuda-64kb-devel~580.126.09~150500.3.85.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-default-devel", rpm:"nvidia-open-driver-G06-signed-cuda-default-devel~580.126.09~150500.3.85.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-64kb~580.126.09_k5.14.21_150500.55.133~150500.3.85.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-default", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-default~580.126.09_k5.14.21_150500.55.133~150500.3.85.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-default-devel", rpm:"nvidia-open-driver-G06-signed-default-devel~580.126.09~150500.3.85.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-kmp-64kb~580.126.09_k5.14.21_150500.55.133~150500.3.85.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default", rpm:"nvidia-open-driver-G06-signed-kmp-default~580.126.09_k5.14.21_150500.55.133~150500.3.85.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-persistenced", rpm:"nvidia-persistenced~580.126.09~150500.12.6.1", rls:"SLES15.0SP5"))) {
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
