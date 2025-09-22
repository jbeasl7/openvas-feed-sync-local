# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0071");
  script_cve_id("CVE-2022-41973", "CVE-2022-41974");
  script_tag(name:"creation_date", value:"2024-03-19 04:12:13 +0000 (Tue, 19 Mar 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-31 19:47:24 +0000 (Mon, 31 Oct 2022)");

  script_name("Mageia: Security Advisory (MGASA-2024-0071)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0071");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0071.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2022:7928");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31017");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/QIGZM5NOOMFDCITOLQEJNNX5SCRQLQVV/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/APSADEAFW42LM3YIFLMFWKMKPGF667O4/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5731-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5366");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/10/24/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'multipath-tools' package(s) announced via the MGASA-2024-0071 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"multipath-tools 0.7.7 through 0.9.x before 0.9.2 allows local users to
obtain root access, as exploited in conjunction with CVE-2022-41974.
Local users able to access /dev/shm can change symlinks in multipathd
due to incorrect symlink handling, which could lead to controlled file
writes outside of the /dev/shm directory. This could be used indirectly
for local privilege escalation to root. (CVE-2022-41973)
multipath-tools 0.7.0 through 0.9.x before 0.9.2 allows local users to
obtain root access, as exploited alone or in conjunction with
CVE-2022-41973. Local users able to write to UNIX domain sockets can
bypass access controls and manipulate the multipath setup. This can lead
to local privilege escalation to root. This occurs because an attacker
can repeat a keyword, which is mishandled because arithmetic ADD is used
instead of bitwise OR. (CVE-2022-41974)");

  script_tag(name:"affected", value:"'multipath-tools' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"kpartx", rpm:"kpartx~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dmmp-devel", rpm:"lib64dmmp-devel~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dmmp0", rpm:"lib64dmmp0~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mpathcmd0", rpm:"lib64mpathcmd0~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mpathpersist0", rpm:"lib64mpathpersist0~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mpathvalid0", rpm:"lib64mpathvalid0~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64multipath-tools-devel", rpm:"lib64multipath-tools-devel~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64multipath0", rpm:"lib64multipath0~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdmmp-devel", rpm:"libdmmp-devel~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdmmp0", rpm:"libdmmp0~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmpathcmd0", rpm:"libmpathcmd0~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmpathpersist0", rpm:"libmpathpersist0~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmpathvalid0", rpm:"libmpathvalid0~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmultipath-tools-devel", rpm:"libmultipath-tools-devel~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmultipath0", rpm:"libmultipath0~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"multipath-tools", rpm:"multipath-tools~0.8.8~2.1.mga9", rls:"MAGEIA9"))) {
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
