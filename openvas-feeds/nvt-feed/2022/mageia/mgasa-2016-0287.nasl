# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0287");
  script_cve_id("CVE-2016-5384");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-15 14:04:25 +0000 (Mon, 15 Aug 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0287)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0287");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0287.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19157");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2016/msg00222.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fontconfig' package(s) announced via the MGASA-2016-0287 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tobias Stoeckmann discovered that cache files are insufficiently
validated in fontconfig, a generic font configuration library. An
attacker can trigger arbitrary free() calls, which in turn allows
double free attacks and therefore arbitrary code execution. In
combination with setuid binaries using crafted cache files, this
could allow privilege escalation (CVE-2016-5384).");

  script_tag(name:"affected", value:"'fontconfig' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"fontconfig", rpm:"fontconfig~2.11.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64fontconfig-devel", rpm:"lib64fontconfig-devel~2.11.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64fontconfig1", rpm:"lib64fontconfig1~2.11.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfontconfig-devel", rpm:"libfontconfig-devel~2.11.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfontconfig1", rpm:"libfontconfig1~2.11.1~4.1.mga5", rls:"MAGEIA5"))) {
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
