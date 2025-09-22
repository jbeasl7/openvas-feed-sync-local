# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886873");
  script_cve_id("CVE-2024-26922", "CVE-2024-26924", "CVE-2024-26980", "CVE-2024-26981", "CVE-2024-26982", "CVE-2024-26983", "CVE-2024-26984", "CVE-2024-26985", "CVE-2024-26986", "CVE-2024-26987", "CVE-2024-26988", "CVE-2024-26989", "CVE-2024-26990", "CVE-2024-26991", "CVE-2024-26992", "CVE-2024-26993", "CVE-2024-26994", "CVE-2024-26995", "CVE-2024-26996", "CVE-2024-26998", "CVE-2024-26999", "CVE-2024-27000", "CVE-2024-27001", "CVE-2024-27002", "CVE-2024-27003", "CVE-2024-27004", "CVE-2024-27005", "CVE-2024-27006", "CVE-2024-27007", "CVE-2024-27008", "CVE-2024-27009", "CVE-2024-27010", "CVE-2024-27011", "CVE-2024-27012", "CVE-2024-27013", "CVE-2024-27014", "CVE-2024-27015", "CVE-2024-27016", "CVE-2024-27017", "CVE-2024-27018", "CVE-2024-27019", "CVE-2024-27020", "CVE-2024-27021", "CVE-2024-27022");
  script_tag(name:"creation_date", value:"2024-05-27 10:50:00 +0000 (Mon, 27 May 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-23 19:37:12 +0000 (Thu, 23 May 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-bc0db39a14)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-bc0db39a14");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-bc0db39a14");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276666");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277155");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277170");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278253");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278255");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278257");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278259");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278261");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278263");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278265");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278267");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278269");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278271");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278276");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278278");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278280");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278282");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278284");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278286");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278288");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278290");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278292");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278294");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278296");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278298");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278300");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278302");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278304");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278309");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278311");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278313");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278315");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278317");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278319");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278321");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278323");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278325");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278328");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278330");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278332");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278334");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278336");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278338");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278340");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278342");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the FEDORA-2024-bc0db39a14 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The 6.8.8 stable kernel update contains a number of important fixes across the tree.");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bpftool-debuginfo", rpm:"bpftool-debuginfo~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-core", rpm:"kernel-core~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-core", rpm:"kernel-debug-core~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-matched", rpm:"kernel-debug-devel-matched~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules", rpm:"kernel-debug-modules~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules-core", rpm:"kernel-debug-modules-core~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules-extra", rpm:"kernel-debug-modules-extra~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules-internal", rpm:"kernel-debug-modules-internal~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-uki-virt", rpm:"kernel-debug-uki-virt~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-aarch64", rpm:"kernel-debuginfo-common-aarch64~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-ppc64le", rpm:"kernel-debuginfo-common-ppc64le~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-s390x", rpm:"kernel-debuginfo-common-s390x~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-matched", rpm:"kernel-devel-matched~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules", rpm:"kernel-modules~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules-core", rpm:"kernel-modules-core~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules-extra", rpm:"kernel-modules-extra~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules-internal", rpm:"kernel-modules-internal~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-selftests-internal", rpm:"kernel-selftests-internal~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uki-virt", rpm:"kernel-uki-virt~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libperf", rpm:"libperf~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libperf-debuginfo", rpm:"libperf-debuginfo~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libperf-devel", rpm:"libperf-devel~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf-debuginfo", rpm:"python3-perf-debuginfo~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rtla", rpm:"rtla~6.8.8~200.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rv", rpm:"rv~6.8.8~200.fc39", rls:"FC39"))) {
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
