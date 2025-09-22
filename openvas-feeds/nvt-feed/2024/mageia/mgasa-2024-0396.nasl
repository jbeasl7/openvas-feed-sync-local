# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0396");
  script_cve_id("CVE-2024-50602");
  script_tag(name:"creation_date", value:"2024-12-23 04:11:08 +0000 (Mon, 23 Dec 2024)");
  script_version("2024-12-23T07:52:44+0000");
  script_tag(name:"last_modification", value:"2024-12-23 07:52:44 +0000 (Mon, 23 Dec 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0396)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0396");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0396.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33864");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/X3V7QAWJ6AWA3YEKX4DEGJFLTQ6ASRC3/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozjs78' package(s) announced via the MGASA-2024-0396 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in libexpat before 2.6.4. There is a crash
within the XML_ResumeParser function because XML_StopParser can
stop/suspend an unstarted parser. (CVE-2024-50602)");

  script_tag(name:"affected", value:"'mozjs78' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64mozjs78", rpm:"lib64mozjs78~78.15.0~7.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mozjs78-devel", rpm:"lib64mozjs78-devel~78.15.0~7.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmozjs78", rpm:"libmozjs78~78.15.0~7.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmozjs78-devel", rpm:"libmozjs78-devel~78.15.0~7.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs78", rpm:"mozjs78~78.15.0~7.2.mga9", rls:"MAGEIA9"))) {
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
