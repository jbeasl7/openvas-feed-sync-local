# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0242");
  script_tag(name:"creation_date", value:"2024-06-28 04:11:20 +0000 (Fri, 28 Jun 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0242)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0242");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0242.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33333");
  script_xref(name:"URL", value:"https://lib.openmpt.org/libopenmpt/2023/06/18/security-updates-0.7.2-0.6.11-0.5.25-release-0.4.37/");
  script_xref(name:"URL", value:"https://lib.openmpt.org/libopenmpt/2024/03/17/security-updates-0.7.5-0.6.14-0.5.28-0.4.40/");
  script_xref(name:"URL", value:"https://lib.openmpt.org/libopenmpt/2024/03/24/security-updates-0.7.6-0.6.15-0.5.29-0.4.41/");
  script_xref(name:"URL", value:"https://lib.openmpt.org/libopenmpt/2024/06/09/security-update-0.7.8-releases-0.6.17-0.5.31-0.4.43/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZVQOQRGG6SYMGVWYOQWZ6D5URKRT4FKC/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libopenmpt' package(s) announced via the MGASA-2024-0242 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Possible out-of-bounds read or write when reading malformed MED files.
(r19389).
[Null-pointer write (32bit platforms) or excessive memory allocation
(64bit platforms) when reading close to 4GiB of data from unseekable
files (r20336, r20338).
Write buffer overflow when reading unseekable files close to 4GiB in
size (r20339).
[Possible out-of-memory (32bit platforms) or excessive memory allocation
(64bit platforms) when reading malformed data from unseekable files
(r20340).
DMF: Possible null-pointer write or excessive memory allocation when
reading DMF files (r20323).
Potential heap out-of-bounds read or write past sample end with
malformed sustain loops in SymMOD files (r20420).
Potential heap out-of-bounds read with malformed Dynamic Studio DSm
files (r20912).");

  script_tag(name:"affected", value:"'libopenmpt' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64openmpt-devel", rpm:"lib64openmpt-devel~0.7.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openmpt0", rpm:"lib64openmpt0~0.7.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt", rpm:"libopenmpt~0.7.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt-devel", rpm:"libopenmpt-devel~0.7.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt0", rpm:"libopenmpt0~0.7.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpt123", rpm:"openmpt123~0.7.8~1.mga9", rls:"MAGEIA9"))) {
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
