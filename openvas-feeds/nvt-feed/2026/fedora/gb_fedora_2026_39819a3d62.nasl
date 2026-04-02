# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.3981997310062");
  script_cve_id("CVE-2026-3497");
  script_tag(name:"creation_date", value:"2026-03-23 04:48:32 +0000 (Mon, 23 Mar 2026)");
  script_version("2026-03-23T06:04:31+0000");
  script_tag(name:"last_modification", value:"2026-03-23 06:04:31 +0000 (Mon, 23 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-39819a3d62)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-39819a3d62");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-39819a3d62");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2442505");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2447289");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2447290");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the FEDORA-2026-39819a3d62 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2026-3497: Fix information disclosure or denial of service due to uninitialized variables in gssapi-keyex");

  script_tag(name:"affected", value:"'openssh' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~9.9p1~13.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~9.9p1~13.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-debuginfo", rpm:"openssh-askpass-debuginfo~9.9p1~13.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~9.9p1~13.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-clients-debuginfo", rpm:"openssh-clients-debuginfo~9.9p1~13.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-debuginfo", rpm:"openssh-debuginfo~9.9p1~13.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-debugsource", rpm:"openssh-debugsource~9.9p1~13.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-keycat", rpm:"openssh-keycat~9.9p1~13.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-keycat-debuginfo", rpm:"openssh-keycat-debuginfo~9.9p1~13.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-keysign", rpm:"openssh-keysign~9.9p1~13.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-keysign-debuginfo", rpm:"openssh-keysign-debuginfo~9.9p1~13.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~9.9p1~13.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server-debuginfo", rpm:"openssh-server-debuginfo~9.9p1~13.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-sk-dummy", rpm:"openssh-sk-dummy~9.9p1~13.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-sk-dummy-debuginfo", rpm:"openssh-sk-dummy-debuginfo~9.9p1~13.fc42", rls:"FC42"))) {
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
