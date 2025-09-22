# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.3342.1");
  script_cve_id("CVE-2023-39325", "CVE-2023-44487", "CVE-2023-45288", "CVE-2024-24786");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 19:32:37 +0000 (Fri, 13 Oct 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3342-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3342-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243342-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230323");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-September/036981.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubernetes1.24' package(s) announced via the SUSE-SU-2024:3342-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kubernetes1.24 fixes the following issues:

- CVE-2023-39325: go1.20: excessive resource consumption when dealing with rapid stream resets. (bsc#1229869)
- CVE-2023-44487: google.golang.org/grpc, kube-apiserver: HTTP/2 rapid reset vulnerability. (bsc#1229869)
- CVE-2023-45288: golang.org/x/net: excessive CPU consumption when processing unlimited sets of headers. (bsc#1229869)
- CVE-2024-24786: github.com/golang/protobuf: infinite loop when unmarshaling invalid JSON. (bsc#1229867)

Bug fixes:

- Update go to version 1.22.5 in build requirements. (bsc#1229858)");

  script_tag(name:"affected", value:"'kubernetes1.24' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-apiserver", rpm:"kubernetes1.24-apiserver~1.24.17~150500.3.22.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client", rpm:"kubernetes1.24-client~1.24.17~150500.3.22.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client-bash-completion", rpm:"kubernetes1.24-client-bash-completion~1.24.17~150500.3.22.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client-common", rpm:"kubernetes1.24-client-common~1.24.17~150500.3.22.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client-fish-completion", rpm:"kubernetes1.24-client-fish-completion~1.24.17~150500.3.22.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-controller-manager", rpm:"kubernetes1.24-controller-manager~1.24.17~150500.3.22.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-kubeadm", rpm:"kubernetes1.24-kubeadm~1.24.17~150500.3.22.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-kubelet", rpm:"kubernetes1.24-kubelet~1.24.17~150500.3.22.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-kubelet-common", rpm:"kubernetes1.24-kubelet-common~1.24.17~150500.3.22.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-proxy", rpm:"kubernetes1.24-proxy~1.24.17~150500.3.22.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-scheduler", rpm:"kubernetes1.24-scheduler~1.24.17~150500.3.22.1", rls:"openSUSELeap15.5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-apiserver", rpm:"kubernetes1.24-apiserver~1.24.17~150500.3.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client", rpm:"kubernetes1.24-client~1.24.17~150500.3.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client-bash-completion", rpm:"kubernetes1.24-client-bash-completion~1.24.17~150500.3.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client-common", rpm:"kubernetes1.24-client-common~1.24.17~150500.3.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client-fish-completion", rpm:"kubernetes1.24-client-fish-completion~1.24.17~150500.3.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-controller-manager", rpm:"kubernetes1.24-controller-manager~1.24.17~150500.3.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-kubeadm", rpm:"kubernetes1.24-kubeadm~1.24.17~150500.3.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-kubelet", rpm:"kubernetes1.24-kubelet~1.24.17~150500.3.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-kubelet-common", rpm:"kubernetes1.24-kubelet-common~1.24.17~150500.3.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-proxy", rpm:"kubernetes1.24-proxy~1.24.17~150500.3.22.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-scheduler", rpm:"kubernetes1.24-scheduler~1.24.17~150500.3.22.1", rls:"openSUSELeap15.6"))) {
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
