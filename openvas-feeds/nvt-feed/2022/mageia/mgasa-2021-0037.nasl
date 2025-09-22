# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0037");
  script_cve_id("CVE-2020-26570", "CVE-2020-26571", "CVE-2020-26572");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-13 17:05:11 +0000 (Tue, 13 Oct 2020)");

  script_name("Mageia: Security Advisory (MGASA-2021-0037)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0037");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0037.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27663");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/EXOHFDMNMO6IDECAGUTB3SJGAGXVRT6S/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc' package(s) announced via the MGASA-2021-0037 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Oberthur smart card software driver in OpenSC before 0.21.0-rc1 has a
heap-based buffer overflow in sc_oberthur_read_file (CVE-2020-26570).

The gemsafe GPK smart card software driver in OpenSC before 0.21.0-rc1 has a
stack-based buffer overflow in sc_pkcs15emu_gemsafeGPK_init (CVE-2020-26571).

The TCOS smart card software driver in OpenSC before 0.21.0-rc1 has a
stack-based buffer overflow in tcos_decipher (CVE-2020-26572).");

  script_tag(name:"affected", value:"'opensc' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64opensc-devel", rpm:"lib64opensc-devel~0.21.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opensc7", rpm:"lib64opensc7~0.21.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smm-local7", rpm:"lib64smm-local7~0.21.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopensc-devel", rpm:"libopensc-devel~0.21.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopensc7", rpm:"libopensc7~0.21.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmm-local7", rpm:"libsmm-local7~0.21.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.21.0~1.mga7", rls:"MAGEIA7"))) {
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
