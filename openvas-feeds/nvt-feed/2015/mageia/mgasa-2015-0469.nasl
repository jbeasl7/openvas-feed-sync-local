# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131151");
  script_cve_id("CVE-2015-8366", "CVE-2015-8367");
  script_tag(name:"creation_date", value:"2015-12-11 05:23:48 +0000 (Fri, 11 Dec 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-24 13:44:25 +0000 (Fri, 24 Jan 2020)");

  script_name("Mageia: Security Advisory (MGASA-2015-0469)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0469");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0469.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17314");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-December/173363.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libraw' package(s) announced via the MGASA-2015-0469 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libraw packages fix security vulnerabilities:

It was found that smal_decode_segment function do not handle index carefully,
which may cause index overflow (CVE-2015-8366).

It was found that phase_one_correct function does not handle memory object's
initialization correctly, which may have unspecified impact (CVE-2015-8367).");

  script_tag(name:"affected", value:"'libraw' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64raw-devel", rpm:"lib64raw-devel~0.16.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64raw10", rpm:"lib64raw10~0.16.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64raw_r10", rpm:"lib64raw_r10~0.16.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw", rpm:"libraw~0.16.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw-devel", rpm:"libraw-devel~0.16.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw-tools", rpm:"libraw-tools~0.16.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw10", rpm:"libraw10~0.16.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw_r10", rpm:"libraw_r10~0.16.2~1.1.mga5", rls:"MAGEIA5"))) {
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
