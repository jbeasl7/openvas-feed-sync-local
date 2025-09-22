# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0278");
  script_cve_id("CVE-2023-52888", "CVE-2024-40947", "CVE-2024-41015", "CVE-2024-41017", "CVE-2024-41018", "CVE-2024-41019", "CVE-2024-41020", "CVE-2024-41022", "CVE-2024-41024", "CVE-2024-41025", "CVE-2024-41027", "CVE-2024-41028", "CVE-2024-41030", "CVE-2024-41031", "CVE-2024-41032", "CVE-2024-41034", "CVE-2024-41035", "CVE-2024-41036", "CVE-2024-41037", "CVE-2024-41038", "CVE-2024-41039", "CVE-2024-41040", "CVE-2024-41041", "CVE-2024-41044", "CVE-2024-41046", "CVE-2024-41047", "CVE-2024-41048", "CVE-2024-41049", "CVE-2024-41050", "CVE-2024-41051", "CVE-2024-41052", "CVE-2024-41053", "CVE-2024-41054", "CVE-2024-41055", "CVE-2024-41056", "CVE-2024-41057", "CVE-2024-41058", "CVE-2024-41059", "CVE-2024-41060", "CVE-2024-41062", "CVE-2024-41063", "CVE-2024-41064", "CVE-2024-41065", "CVE-2024-41066", "CVE-2024-41068", "CVE-2024-41069", "CVE-2024-41070", "CVE-2024-41072", "CVE-2024-41073", "CVE-2024-41074", "CVE-2024-41075", "CVE-2024-41076", "CVE-2024-41077", "CVE-2024-41078", "CVE-2024-41079", "CVE-2024-41081", "CVE-2024-41090", "CVE-2024-41091", "CVE-2024-42067", "CVE-2024-42068", "CVE-2024-42100", "CVE-2024-42101", "CVE-2024-42102", "CVE-2024-42103", "CVE-2024-42104", "CVE-2024-42105", "CVE-2024-42106", "CVE-2024-42109", "CVE-2024-42110", "CVE-2024-42113", "CVE-2024-42115", "CVE-2024-42116", "CVE-2024-42119", "CVE-2024-42120", "CVE-2024-42121", "CVE-2024-42124", "CVE-2024-42126", "CVE-2024-42127", "CVE-2024-42128", "CVE-2024-42130", "CVE-2024-42131", "CVE-2024-42132", "CVE-2024-42133", "CVE-2024-42135", "CVE-2024-42136", "CVE-2024-42137", "CVE-2024-42138", "CVE-2024-42140", "CVE-2024-42141", "CVE-2024-42142", "CVE-2024-42143", "CVE-2024-42144", "CVE-2024-42145", "CVE-2024-42147", "CVE-2024-42148", "CVE-2024-42152", "CVE-2024-42153", "CVE-2024-42154", "CVE-2024-42157", "CVE-2024-42159", "CVE-2024-42160", "CVE-2024-42161", "CVE-2024-42223", "CVE-2024-42224", "CVE-2024-42225", "CVE-2024-42226", "CVE-2024-42228", "CVE-2024-42229", "CVE-2024-42230");
  script_tag(name:"creation_date", value:"2024-08-07 11:24:47 +0000 (Wed, 07 Aug 2024)");
  script_version("2024-10-03T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-10-03 05:05:33 +0000 (Thu, 03 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-02 14:29:26 +0000 (Fri, 02 Aug 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0278)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0278");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0278.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33447");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.38");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.39");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.40");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.41");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.42");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.43");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2024-0278 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vanilla upstream kernel version 6.6.43 fix bugs and vulnerabilities.
For information about the vulnerabilities see the links.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~6.6.43~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel", rpm:"kernel-linus-devel~6.6.43~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~6.6.43~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~6.6.43~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~6.6.43~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source", rpm:"kernel-linus-source~6.6.43~1.mga9", rls:"MAGEIA9"))) {
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
