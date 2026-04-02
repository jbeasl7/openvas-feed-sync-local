# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.989798497975100977");
  script_cve_id("CVE-2026-3497");
  script_tag(name:"creation_date", value:"2026-03-20 04:37:32 +0000 (Fri, 20 Mar 2026)");
  script_version("2026-03-20T05:55:14+0000");
  script_tag(name:"last_modification", value:"2026-03-20 05:55:14 +0000 (Fri, 20 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-bab4aa5da7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-bab4aa5da7");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-bab4aa5da7");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2442505");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2447289");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2447290");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the FEDORA-2026-bab4aa5da7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2026-3497: Fix information disclosure or denial of service due to uninitialized variables in gssapi-keyex");

  script_tag(name:"affected", value:"'openssh' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~10.0p1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~10.0p1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-debuginfo", rpm:"openssh-askpass-debuginfo~10.0p1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~10.0p1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-clients-debuginfo", rpm:"openssh-clients-debuginfo~10.0p1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-debuginfo", rpm:"openssh-debuginfo~10.0p1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-debugsource", rpm:"openssh-debugsource~10.0p1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-keycat", rpm:"openssh-keycat~10.0p1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-keycat-debuginfo", rpm:"openssh-keycat-debuginfo~10.0p1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-keysign", rpm:"openssh-keysign~10.0p1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-keysign-debuginfo", rpm:"openssh-keysign-debuginfo~10.0p1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~10.0p1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server-debuginfo", rpm:"openssh-server-debuginfo~10.0p1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-sk-dummy", rpm:"openssh-sk-dummy~10.0p1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-sk-dummy-debuginfo", rpm:"openssh-sk-dummy-debuginfo~10.0p1~7.fc43", rls:"FC43"))) {
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
