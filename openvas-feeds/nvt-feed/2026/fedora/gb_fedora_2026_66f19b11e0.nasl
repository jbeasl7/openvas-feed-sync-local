# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.661021998111010");
  script_cve_id("CVE-2026-3608");
  script_tag(name:"creation_date", value:"2026-04-08 04:54:07 +0000 (Wed, 08 Apr 2026)");
  script_version("2026-04-08T06:10:32+0000");
  script_tag(name:"last_modification", value:"2026-04-08 06:10:32 +0000 (Wed, 08 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-25 09:16:25 +0000 (Wed, 25 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-66f19b11e0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-66f19b11e0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-66f19b11e0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2451141");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2451621");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kea' package(s) announced via the FEDORA-2026-66f19b11e0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- New version 3.0.3 (rhbz#2451141)
- Fixes CVE-2026-3608 (rhbz#2451621)");

  script_tag(name:"affected", value:"'kea' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"kea", rpm:"kea~3.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-debuginfo", rpm:"kea-debuginfo~3.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-debugsource", rpm:"kea-debugsource~3.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-devel", rpm:"kea-devel~3.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-devel-debuginfo", rpm:"kea-devel-debuginfo~3.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-doc", rpm:"kea-doc~3.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-hooks", rpm:"kea-hooks~3.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-hooks-debuginfo", rpm:"kea-hooks-debuginfo~3.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-keama", rpm:"kea-keama~3.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-keama-debuginfo", rpm:"kea-keama-debuginfo~3.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-libs", rpm:"kea-libs~3.0.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-libs-debuginfo", rpm:"kea-libs-debuginfo~3.0.3~1.fc42", rls:"FC42"))) {
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
