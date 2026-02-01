# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.8989923981003");
  script_tag(name:"creation_date", value:"2026-01-12 04:26:16 +0000 (Mon, 12 Jan 2026)");
  script_version("2026-01-12T05:50:06+0000");
  script_tag(name:"last_modification", value:"2026-01-12 05:50:06 +0000 (Mon, 12 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-8b992398d3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-8b992398d3");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-8b992398d3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nginx' package(s) announced via the FEDORA-2026-8b992398d3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- cleanups and fixes
- remove RHEL 7 compatibility
- add RHEL 9 compatibility and EOL comments
- restore RHEL 8 compatibility");

  script_tag(name:"affected", value:"'nginx' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"nginx", rpm:"nginx~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-all-modules", rpm:"nginx-all-modules~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-core", rpm:"nginx-core~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-core-debuginfo", rpm:"nginx-core-debuginfo~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debuginfo", rpm:"nginx-debuginfo~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debugsource", rpm:"nginx-debugsource~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-filesystem", rpm:"nginx-filesystem~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-devel", rpm:"nginx-mod-devel~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-image-filter", rpm:"nginx-mod-http-image-filter~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-image-filter-debuginfo", rpm:"nginx-mod-http-image-filter-debuginfo~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-perl", rpm:"nginx-mod-http-perl~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-perl-debuginfo", rpm:"nginx-mod-http-perl-debuginfo~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-xslt-filter", rpm:"nginx-mod-http-xslt-filter~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-xslt-filter-debuginfo", rpm:"nginx-mod-http-xslt-filter-debuginfo~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-mail", rpm:"nginx-mod-mail~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-mail-debuginfo", rpm:"nginx-mod-mail-debuginfo~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-stream", rpm:"nginx-mod-stream~1.28.1~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-stream-debuginfo", rpm:"nginx-mod-stream-debuginfo~1.28.1~3.fc42", rls:"FC42"))) {
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
