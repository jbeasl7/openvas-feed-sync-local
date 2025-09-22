# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0241");
  script_cve_id("CVE-2023-33551", "CVE-2023-33552");
  script_tag(name:"creation_date", value:"2024-06-28 04:11:20 +0000 (Fri, 28 Jun 2024)");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-12 14:27:41 +0000 (Mon, 12 Jun 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0241)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0241");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0241.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32272");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FHOIRL6XH5NYR3LYI3KP5DE4SDSQWR7W/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'erofs-utils' package(s) announced via the MGASA-2024-0241 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Heap Buffer Overflow in the erofsfsck_dirent_iter function in
fsck/main.c in erofs-utils v1.6 allows remote attackers to execute
arbitrary code via a crafted erofs filesystem image.");

  script_tag(name:"affected", value:"'erofs-utils' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"erofs-fuse", rpm:"erofs-fuse~1.7.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erofs-utils", rpm:"erofs-utils~1.7.1~1.mga9", rls:"MAGEIA9"))) {
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
