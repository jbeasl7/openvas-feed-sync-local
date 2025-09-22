# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0214");
  script_cve_id("CVE-2017-14731", "CVE-2017-2816", "CVE-2017-2920");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-13 14:28:11 +0000 (Fri, 13 Oct 2017)");

  script_name("Mageia: Security Advisory (MGASA-2018-0214)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0214");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0214.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22878");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/O2W5PV4QMNKEUZEPKO2GNBDRLIDSVDZM/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libofx' package(s) announced via the MGASA-2018-0214 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An exploitable buffer overflow vulnerability exists in the tag parsing
functionality of LibOFX 0.9.11. A specially crafted OFX file can cause a
write out of bounds resulting in a buffer overflow on the stack. An
attacker can construct a malicious OFX file to trigger this
vulnerability (CVE-2017-2816).

An exploitable buffer overflow vulnerability exists in the tag parsing
functionality of LibOFX 0.9.11. A specially crafted OFX file can cause a
write out of bounds resulting in a buffer overflow on the stack. An
attacker can construct a malicious OFX file to trigger this
vulnerability (CVE-2017-2920).

ofx_proc_file in ofx_preproc.cpp in LibOFX 0.9.12 allows remote
attackers to cause a denial of service (heap-based buffer over-read and
application crash) via a crafted file, as demonstrated by an ofxdump
call (CVE-2017-14731).");

  script_tag(name:"affected", value:"'libofx' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ofx-devel", rpm:"lib64ofx-devel~0.9.10~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ofx6", rpm:"lib64ofx6~0.9.10~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libofx", rpm:"libofx~0.9.10~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libofx-devel", rpm:"libofx-devel~0.9.10~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libofx6", rpm:"libofx6~0.9.10~2.mga6", rls:"MAGEIA6"))) {
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
