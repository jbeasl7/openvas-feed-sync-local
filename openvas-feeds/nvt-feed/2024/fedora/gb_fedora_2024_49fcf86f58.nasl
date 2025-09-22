# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886745");
  script_cve_id("CVE-2024-21823", "CVE-2024-27398", "CVE-2024-27399", "CVE-2024-27400", "CVE-2024-27401");
  script_tag(name:"creation_date", value:"2024-05-27 10:46:08 +0000 (Mon, 27 May 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-49fcf86f58)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-49fcf86f58");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-49fcf86f58");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276325");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279678");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279734");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280396");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280408");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280461");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280463");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280465");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the FEDORA-2024-49fcf86f58 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The 6.8.10 stable kernel update contains a number of important fixes across the tree");

  script_tag(name:"affected", value:"'kernel' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bpftool-debuginfo", rpm:"bpftool-debuginfo~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-core", rpm:"kernel-core~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-core", rpm:"kernel-debug-core~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-matched", rpm:"kernel-debug-devel-matched~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules", rpm:"kernel-debug-modules~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules-core", rpm:"kernel-debug-modules-core~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules-extra", rpm:"kernel-debug-modules-extra~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules-internal", rpm:"kernel-debug-modules-internal~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-uki-virt", rpm:"kernel-debug-uki-virt~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-aarch64", rpm:"kernel-debuginfo-common-aarch64~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-ppc64le", rpm:"kernel-debuginfo-common-ppc64le~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-s390x", rpm:"kernel-debuginfo-common-s390x~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-matched", rpm:"kernel-devel-matched~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules", rpm:"kernel-modules~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules-core", rpm:"kernel-modules-core~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules-extra", rpm:"kernel-modules-extra~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules-internal", rpm:"kernel-modules-internal~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-selftests-internal", rpm:"kernel-selftests-internal~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uki-virt", rpm:"kernel-uki-virt~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libperf", rpm:"libperf~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libperf-debuginfo", rpm:"libperf-debuginfo~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libperf-devel", rpm:"libperf-devel~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf-debuginfo", rpm:"python3-perf-debuginfo~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rtla", rpm:"rtla~6.8.10~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rv", rpm:"rv~6.8.10~200.fc39", rls:"FC39"))) {
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
