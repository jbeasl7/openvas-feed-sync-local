# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0056");
  script_cve_id("CVE-2014-9328");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0056)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0056");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0056.html");
  script_xref(name:"URL", value:"http://blog.clamav.net/2015/01/clamav-0986-has-been-released.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15155");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the MGASA-2015-0056 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ClamAV 0.98.6 is a maintenance release to fix some bugs, some of them being
security bugs:

Fix a heap out of bounds condition with crafted Yoda's crypter files.
This issue was discovered by Felix Groebert of the Google Security Team.

Fix a heap out of bounds condition with crafted mew packer files.
This issue was discovered by Felix Groebert of the Google Security Team.

Fix a heap out of bounds condition with crafted upx packer files.
This issue was discovered by Kevin Szkudlapski of Quarkslab.

Fix a heap out of bounds condition with crafted upack packer files.
This issue was discovered by Sebastian Andrzej Siewior (CVE-2014-9328).

Compensate a crash due to incorrect compiler optimization when handling crafted
petite packer files. This issue was discovered by Sebastian Andrzej Siewior.");

  script_tag(name:"affected", value:"'clamav' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.98.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~0.98.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamd", rpm:"clamd~0.98.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64clamav-devel", rpm:"lib64clamav-devel~0.98.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64clamav6", rpm:"lib64clamav6~0.98.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav-devel", rpm:"libclamav-devel~0.98.6~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav6", rpm:"libclamav6~0.98.6~1.mga4", rls:"MAGEIA4"))) {
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
