# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856976");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2024-0131", "CVE-2024-0147", "CVE-2024-0149", "CVE-2024-0150", "CVE-2024-53869");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-01-22 05:01:41 +0000 (Wed, 22 Jan 2025)");
  script_name("openSUSE: Security Advisory for nvidia (SUSE-SU-2025:0208-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0208-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/W62IRYVH7B2VEA4GDOLEFC5X55NCMB6L");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia'
  package(s) announced via the SUSE-SU-2025:0208-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nvidia-open-driver-G06-signed fixes the following issues:

  * Update to 550.144.03 (bsc#1235461, bsc#1235871)

  * fixes CVE-2024-0131, CVE-2024-0147, CVE-2024-0149, CVE-2024-0150,
      CVE-2024-53869");

  script_tag(name:"affected", value:"'nvidia' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-azure", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-azure~565.57.01_k5.14.21_150500.31~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-azure-debuginfo", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-azure-debuginfo~565.57.01_k5.14.21_150500.31~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-azure-devel", rpm:"nvidia-open-driver-G06-signed-cuda-azure-devel~565.57.01~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-azure-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-azure-debuginfo~550.144.03_k5.14.21_150500.31~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-azure-devel", rpm:"nvidia-open-driver-G06-signed-azure-devel~550.144.03~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-azure", rpm:"nvidia-open-driver-G06-signed-kmp-azure~550.144.03_k5.14.21_150500.31~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-gspx-G06-cuda", rpm:"kernel-firmware-nvidia-gspx-G06-cuda~565.57.01~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-debugsource", rpm:"nvidia-open-driver-G06-signed-cuda-debugsource~565.57.01~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-debugsource", rpm:"nvidia-open-driver-G06-signed-debugsource~550.144.03~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-default-debuginfo~550.144.03_k5.14.21_150500.53~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-default-devel", rpm:"nvidia-open-driver-G06-signed-default-devel~550.144.03~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default", rpm:"nvidia-open-driver-G06-signed-kmp-default~550.144.03_k5.14.21_150500.53~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-default-devel", rpm:"nvidia-open-driver-G06-signed-cuda-default-devel~565.57.01~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-default", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-default~565.57.01_k5.14.21_150500.53~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-default-debuginfo", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-default-debuginfo~565.57.01_k5.14.21_150500.53~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nv-prefer-signed-open-driver", rpm:"nv-prefer-signed-open-driver~565.57.01~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-64kb-devel", rpm:"nvidia-open-driver-G06-signed-64kb-devel~550.144.03~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-64kb-debuginfo", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-64kb-debuginfo~565.57.01_k5.14.21_150500.53~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-64kb-debuginfo~550.144.03_k5.14.21_150500.53~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-64kb-devel", rpm:"nvidia-open-driver-G06-signed-cuda-64kb-devel~565.57.01~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-kmp-64kb~550.144.03_k5.14.21_150500.53~150500.3.70.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-cuda-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-cuda-kmp-64kb~565.57.01_k5.14.21_150500.53~150500.3.70.2", rls:"openSUSELeap15.5"))) {
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