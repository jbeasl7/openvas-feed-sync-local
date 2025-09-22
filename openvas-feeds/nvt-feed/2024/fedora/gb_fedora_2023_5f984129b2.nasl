# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.5102984129982");
  script_cve_id("CVE-2023-39325", "CVE-2023-46129");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 19:01:15 +0000 (Wed, 08 Nov 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-5f984129b2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-5f984129b2");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-5f984129b2");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247715");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247716");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2248318");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2248394");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-nats-io, golang-github-nats-io-jwt-2, golang-github-nats-io-nkeys, golang-github-nats-io-streaming-server, nats-server' package(s) announced via the FEDORA-2023-5f984129b2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated NATS stack for CVE-2023-39325 and CVE-2023-46129");

  script_tag(name:"affected", value:"'golang-github-nats-io, golang-github-nats-io-jwt-2, golang-github-nats-io-nkeys, golang-github-nats-io-streaming-server, nats-server' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"compat-golang-github-nats-io-devel", rpm:"compat-golang-github-nats-io-devel~1.31.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"compat-golang-github-nats-io-gnatsd-devel", rpm:"compat-golang-github-nats-io-gnatsd-devel~2.10.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"compat-golang-github-nats-io-jwt-2-devel", rpm:"compat-golang-github-nats-io-jwt-2-devel~2.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"compat-golang-github-nats-io-server-2-devel", rpm:"compat-golang-github-nats-io-server-2-devel~2.10.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nats-io", rpm:"golang-github-nats-io~1.31.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nats-io-devel", rpm:"golang-github-nats-io-devel~1.31.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nats-io-jwt-2", rpm:"golang-github-nats-io-jwt-2~2.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nats-io-jwt-devel", rpm:"golang-github-nats-io-jwt-devel~2.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nats-io-nkeys", rpm:"golang-github-nats-io-nkeys~0.4.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nats-io-nkeys-debuginfo", rpm:"golang-github-nats-io-nkeys-debuginfo~0.4.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nats-io-nkeys-debugsource", rpm:"golang-github-nats-io-nkeys-debugsource~0.4.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nats-io-nkeys-devel", rpm:"golang-github-nats-io-nkeys-devel~0.4.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nats-io-server-devel", rpm:"golang-github-nats-io-server-devel~2.10.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nats-io-streaming-server", rpm:"golang-github-nats-io-streaming-server~0.25.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nats-io-streaming-server-debuginfo", rpm:"golang-github-nats-io-streaming-server-debuginfo~0.25.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nats-io-streaming-server-debugsource", rpm:"golang-github-nats-io-streaming-server-debugsource~0.25.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nats-io-streaming-server-devel", rpm:"golang-github-nats-io-streaming-server-devel~0.25.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nats-server", rpm:"nats-server~2.10.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nats-server-debuginfo", rpm:"nats-server-debuginfo~2.10.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nats-server-debugsource", rpm:"nats-server-debugsource~2.10.5~1.fc40", rls:"FC40"))) {
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
