# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130077");
  script_cve_id("CVE-2015-1868", "CVE-2015-5470");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:26 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0301)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0301");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0301.html");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2015-0189.html");
  script_xref(name:"URL", value:"http://blog.powerdns.com/2015/06/09/authoritative-server-3-4-5-3-3-3-and-recursor-3-7-3-3-6-4-released/");
  script_xref(name:"URL", value:"http://doc.powerdns.com/md/security/powerdns-advisory-2015-01/");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2015-07/msg00049.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/07/10/8");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16320");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns, pdns-recursor' package(s) announced via the MGASA-2015-0301 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In MGASA-2015-0189, the pdns and pdns-recursor packages were updated to
fix a denial of service issue (CVE-2015-1868). The fix was incomplete.
The packages have been updated again to versions 3.3.3 and 3.6.4,
respectively, to completely fix this issue.");

  script_tag(name:"affected", value:"'pdns, pdns-recursor' package(s) on Mageia 4, Mageia 5.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"pdns", rpm:"pdns~3.3.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-geo", rpm:"pdns-backend-geo~3.3.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-ldap", rpm:"pdns-backend-ldap~3.3.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-mysql", rpm:"pdns-backend-mysql~3.3.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-pgsql", rpm:"pdns-backend-pgsql~3.3.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-pipe", rpm:"pdns-backend-pipe~3.3.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-sqlite", rpm:"pdns-backend-sqlite~3.3.3~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-recursor", rpm:"pdns-recursor~3.6.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"pdns", rpm:"pdns~3.3.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-geo", rpm:"pdns-backend-geo~3.3.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-ldap", rpm:"pdns-backend-ldap~3.3.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-mysql", rpm:"pdns-backend-mysql~3.3.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-pgsql", rpm:"pdns-backend-pgsql~3.3.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-pipe", rpm:"pdns-backend-pipe~3.3.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-sqlite", rpm:"pdns-backend-sqlite~3.3.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-recursor", rpm:"pdns-recursor~3.6.4~1.mga5", rls:"MAGEIA5"))) {
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
