# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885216");
  script_tag(name:"creation_date", value:"2023-11-05 02:21:18 +0000 (Sun, 05 Nov 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2023-1c069009b8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-1c069009b8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-1c069009b8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2232409");
  script_xref(name:"URL", value:"https://downloads.isc.org/isc/bind9/9.19.17/RELEASE-NOTES-bind-9.19.17.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9-next' package(s) announced via the FEDORA-2023-1c069009b8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Upstream [release notes]([link moved to references])");

  script_tag(name:"affected", value:"'bind9-next' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind9-next", rpm:"bind9-next~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-chroot", rpm:"bind9-next-chroot~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-debuginfo", rpm:"bind9-next-debuginfo~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-debugsource", rpm:"bind9-next-debugsource~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-devel", rpm:"bind9-next-devel~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-filesystem", rpm:"bind9-next-dlz-filesystem~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-filesystem-debuginfo", rpm:"bind9-next-dlz-filesystem-debuginfo~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-ldap", rpm:"bind9-next-dlz-ldap~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-ldap-debuginfo", rpm:"bind9-next-dlz-ldap-debuginfo~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-mysql", rpm:"bind9-next-dlz-mysql~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-mysql-debuginfo", rpm:"bind9-next-dlz-mysql-debuginfo~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-sqlite3", rpm:"bind9-next-dlz-sqlite3~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dlz-sqlite3-debuginfo", rpm:"bind9-next-dlz-sqlite3-debuginfo~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dnssec-utils", rpm:"bind9-next-dnssec-utils~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dnssec-utils-debuginfo", rpm:"bind9-next-dnssec-utils-debuginfo~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-doc", rpm:"bind9-next-doc~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-libs", rpm:"bind9-next-libs~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-libs-debuginfo", rpm:"bind9-next-libs-debuginfo~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-license", rpm:"bind9-next-license~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-utils", rpm:"bind9-next-utils~9.19.17~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-utils-debuginfo", rpm:"bind9-next-utils-debuginfo~9.19.17~1.fc39", rls:"FC39"))) {
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
