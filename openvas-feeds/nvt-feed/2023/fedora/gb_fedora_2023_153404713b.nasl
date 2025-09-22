# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885519");
  script_cve_id("CVE-2023-48795");
  script_tag(name:"creation_date", value:"2023-12-30 02:16:31 +0000 (Sat, 30 Dec 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-153404713b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-153404713b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-153404713b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254210");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255053");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'proftpd' package(s) announced via the FEDORA-2023-153404713b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2023-48795 (Terrapin SSH protocol attack), affecting mod_sftp.");

  script_tag(name:"affected", value:"'proftpd' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"proftpd", rpm:"proftpd~1.3.8b~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-debuginfo", rpm:"proftpd-debuginfo~1.3.8b~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-debugsource", rpm:"proftpd-debugsource~1.3.8b~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-devel", rpm:"proftpd-devel~1.3.8b~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-ldap", rpm:"proftpd-ldap~1.3.8b~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-ldap-debuginfo", rpm:"proftpd-ldap-debuginfo~1.3.8b~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mysql", rpm:"proftpd-mysql~1.3.8b~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mysql-debuginfo", rpm:"proftpd-mysql-debuginfo~1.3.8b~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-postgresql", rpm:"proftpd-postgresql~1.3.8b~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-postgresql-debuginfo", rpm:"proftpd-postgresql-debuginfo~1.3.8b~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-sqlite", rpm:"proftpd-sqlite~1.3.8b~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-sqlite-debuginfo", rpm:"proftpd-sqlite-debuginfo~1.3.8b~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-utils", rpm:"proftpd-utils~1.3.8b~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-utils-debuginfo", rpm:"proftpd-utils-debuginfo~1.3.8b~1.fc39", rls:"FC39"))) {
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
