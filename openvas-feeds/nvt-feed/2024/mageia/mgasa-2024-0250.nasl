# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0250");
  script_cve_id("CVE-2024-6387");
  script_tag(name:"creation_date", value:"2024-07-04 04:11:34 +0000 (Thu, 04 Jul 2024)");
  script_version("2024-07-09T05:05:54+0000");
  script_tag(name:"last_modification", value:"2024-07-09 05:05:54 +0000 (Tue, 09 Jul 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-05 15:10:37 +0000 (Fri, 05 Jul 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0250)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0250");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0250.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33346");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2024/msg00135.html");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/01/3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the MGASA-2024-0250 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"regreSSHion: RCE in OpenSSH's server, on glibc-based Linux systems.
(CVE-2024-6387)");

  script_tag(name:"affected", value:"'openssh' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~9.3p1~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-common", rpm:"openssh-askpass-common~9.3p1~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~9.3p1~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~9.3p1~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-keycat", rpm:"openssh-keycat~9.3p1~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~9.3p1~2.2.mga9", rls:"MAGEIA9"))) {
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
