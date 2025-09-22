# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131291");
  script_cve_id("CVE-2016-2167", "CVE-2016-2168");
  script_tag(name:"creation_date", value:"2016-05-09 11:17:54 +0000 (Mon, 09 May 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-06 17:51:06 +0000 (Fri, 06 May 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0161)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0161");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0161.html");
  script_xref(name:"URL", value:"http://mail-archives.apache.org/mod_mbox/subversion-announce/201604.mbox/%3CCAP_GPNgJet+7_MAhomFVOXPgLtewcUw9w=k9zdPCkq5tvPxVMA@mail.gmail.com%3E");
  script_xref(name:"URL", value:"http://subversion.apache.org/security/CVE-2016-2167-advisory.txt");
  script_xref(name:"URL", value:"http://subversion.apache.org/security/CVE-2016-2168-advisory.txt");
  script_xref(name:"URL", value:"http://svn.apache.org/repos/asf/subversion/tags/1.8.16/CHANGES");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18299");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3561");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'subversion' package(s) announced via the MGASA-2016-0161 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated subversion packages fix security vulnerabilities:

Daniel Shahaf and James McCoy discovered that an implementation error in the
authentication against the Cyrus SASL library would permit a remote user to
specify a realm string which is a prefix of the expected realm string and
potentially allowing a user to authenticate using the wrong realm
(CVE-2016-2167).

Ivan Zhakov of VisualSVN discovered a remotely triggerable denial of service
vulnerability in the mod_authz_svn module during COPY or MOVE authorization
check. An authenticated remote attacker could take advantage of this flaw to
cause a denial of service (Subversion server crash) via COPY or MOVE requests
with specially crafted header (CVE-2016-2168).");

  script_tag(name:"affected", value:"'subversion' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dav_svn", rpm:"apache-mod_dav_svn~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64svn-gnome-keyring0", rpm:"lib64svn-gnome-keyring0~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64svn-kwallet0", rpm:"lib64svn-kwallet0~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64svn0", rpm:"lib64svn0~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64svnjavahl1", rpm:"lib64svnjavahl1~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvn-gnome-keyring0", rpm:"libsvn-gnome-keyring0~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvn-kwallet0", rpm:"libsvn-kwallet0~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvn0", rpm:"libsvn0~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsvnjavahl1", rpm:"libsvnjavahl1~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SVN", rpm:"perl-SVN~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-svn-devel", rpm:"perl-svn-devel~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-svn", rpm:"python-svn~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-svn-devel", rpm:"python-svn-devel~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-svn", rpm:"ruby-svn~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-svn-devel", rpm:"ruby-svn-devel~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-doc", rpm:"subversion-doc~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-gnome-keyring-devel", rpm:"subversion-gnome-keyring-devel~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-kwallet-devel", rpm:"subversion-kwallet-devel~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-server", rpm:"subversion-server~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-tools", rpm:"subversion-tools~1.8.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"svn-javahl", rpm:"svn-javahl~1.8.16~1.mga5", rls:"MAGEIA5"))) {
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
