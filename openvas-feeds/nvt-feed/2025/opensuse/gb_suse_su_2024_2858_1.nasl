# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.2858.1");
  script_cve_id("CVE-2021-25743");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-25 17:15:24 +0000 (Tue, 25 Jan 2022)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:2858-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2858-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242858-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194400");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-August/036378.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubernetes1.23' package(s) announced via the SUSE-SU-2024:2858-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kubernetes1.23 fixes the following issues:

- CVE-2021-25743: Fixed sanitization of raw data of escape, meta or control sequences before output it to terminal (bsc#1194400)");

  script_tag(name:"affected", value:"'kubernetes1.23' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-apiserver", rpm:"kubernetes1.23-apiserver~1.23.17~150500.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-client", rpm:"kubernetes1.23-client~1.23.17~150500.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-client-bash-completion", rpm:"kubernetes1.23-client-bash-completion~1.23.17~150500.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-client-common", rpm:"kubernetes1.23-client-common~1.23.17~150500.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-client-fish-completion", rpm:"kubernetes1.23-client-fish-completion~1.23.17~150500.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-controller-manager", rpm:"kubernetes1.23-controller-manager~1.23.17~150500.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-kubeadm", rpm:"kubernetes1.23-kubeadm~1.23.17~150500.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-kubelet", rpm:"kubernetes1.23-kubelet~1.23.17~150500.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-kubelet-common", rpm:"kubernetes1.23-kubelet-common~1.23.17~150500.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-proxy", rpm:"kubernetes1.23-proxy~1.23.17~150500.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-scheduler", rpm:"kubernetes1.23-scheduler~1.23.17~150500.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-apiserver", rpm:"kubernetes1.23-apiserver~1.23.17~150500.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-client", rpm:"kubernetes1.23-client~1.23.17~150500.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-client-bash-completion", rpm:"kubernetes1.23-client-bash-completion~1.23.17~150500.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-client-common", rpm:"kubernetes1.23-client-common~1.23.17~150500.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-client-fish-completion", rpm:"kubernetes1.23-client-fish-completion~1.23.17~150500.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-controller-manager", rpm:"kubernetes1.23-controller-manager~1.23.17~150500.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-kubeadm", rpm:"kubernetes1.23-kubeadm~1.23.17~150500.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-kubelet", rpm:"kubernetes1.23-kubelet~1.23.17~150500.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-kubelet-common", rpm:"kubernetes1.23-kubelet-common~1.23.17~150500.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-proxy", rpm:"kubernetes1.23-proxy~1.23.17~150500.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.23-scheduler", rpm:"kubernetes1.23-scheduler~1.23.17~150500.3.15.1", rls:"openSUSELeap15.6"))) {
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
