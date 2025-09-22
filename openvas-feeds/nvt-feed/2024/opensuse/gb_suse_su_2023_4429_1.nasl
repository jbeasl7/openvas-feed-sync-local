# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833271");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-31022");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-13 19:19:02 +0000 (Mon, 13 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:16:23 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for kernel (SUSE-SU-2023:4429-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4429-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EHTZOYPEXRRI66KITLI3X63KOYEOHMVP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the SUSE-SU-2023:4429-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware-nvidia-gspx-G06, nvidia-open-driver-G06-signed
  fixes the following issues:

  Security issues fixed:

  * CVE-2023-31022: Fixed NULL ptr deref in kernel module layer

  Changes in kernel-firmware-nvidia-gspx-G06:

  * update firmware to version 535.129.03

  Changes in nvidia-open-driver-G06-signed:

  * Update to version 535.129.03

  ##");

  script_tag(name:"affected", value:"'kernel' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-gspx-G06", rpm:"kernel-firmware-nvidia-gspx-G06~535.129.03~150400.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-azure-devel", rpm:"nvidia-open-driver-G06-signed-azure-devel~535.129.03~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-azure", rpm:"nvidia-open-driver-G06-signed-kmp-azure~535.129.03_k5.14.21_150400.14.72~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-azure-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-azure-debuginfo~535.129.03_k5.14.21_150400.14.72~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-debugsource", rpm:"nvidia-open-driver-G06-signed-debugsource~535.129.03~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-default-devel", rpm:"nvidia-open-driver-G06-signed-default-devel~535.129.03~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-default-debuginfo~535.129.03_k5.14.21_150400.24.92~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default", rpm:"nvidia-open-driver-G06-signed-kmp-default~535.129.03_k5.14.21_150400.24.92~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-kmp-64kb~535.129.03_k5.14.21_150400.24.92~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-64kb-debuginfo~535.129.03_k5.14.21_150400.24.92~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-64kb-devel", rpm:"nvidia-open-driver-G06-signed-64kb-devel~535.129.03~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-gspx-G06", rpm:"kernel-firmware-nvidia-gspx-G06~535.129.03~150400.9.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-azure-devel", rpm:"nvidia-open-driver-G06-signed-azure-devel~535.129.03~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-azure", rpm:"nvidia-open-driver-G06-signed-kmp-azure~535.129.03_k5.14.21_150400.14.72~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-azure-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-azure-debuginfo~535.129.03_k5.14.21_150400.14.72~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-debugsource", rpm:"nvidia-open-driver-G06-signed-debugsource~535.129.03~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-default-devel", rpm:"nvidia-open-driver-G06-signed-default-devel~535.129.03~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-default-debuginfo~535.129.03_k5.14.21_150400.24.92~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-default", rpm:"nvidia-open-driver-G06-signed-kmp-default~535.129.03_k5.14.21_150400.24.92~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb", rpm:"nvidia-open-driver-G06-signed-kmp-64kb~535.129.03_k5.14.21_150400.24.92~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-kmp-64kb-debuginfo", rpm:"nvidia-open-driver-G06-signed-kmp-64kb-debuginfo~535.129.03_k5.14.21_150400.24.92~150400.9.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-open-driver-G06-signed-64kb-devel", rpm:"nvidia-open-driver-G06-signed-64kb-devel~535.129.03~150400.9.27.1", rls:"openSUSELeap15.4"))) {
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