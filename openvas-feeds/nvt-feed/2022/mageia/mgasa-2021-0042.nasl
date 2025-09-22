# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0042");
  script_cve_id("CVE-2021-23239", "CVE-2021-23240");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-14 21:32:10 +0000 (Thu, 14 Jan 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0042)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0042");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0042.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28067");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/01/11/2");
  script_xref(name:"URL", value:"https://www.sudo.ws/stable.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the MGASA-2021-0042 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The sudoedit personality of Sudo before 1.9.5 may allow a local unprivileged
user to perform arbitrary directory-existence tests by winning a sudo_edit.c
race condition in replacing a user-controlled directory by a symlink to an
arbitrary path. (CVE-2021-23239).

selinux_edit_copy_tfiles in sudoedit in Sudo before 1.9.5 allows a local
unprivileged user to gain file ownership and escalate privileges by replacing
a temporary file with a symlink to an arbitrary file target. This affects
SELinux RBAC support in permissive mode. Machines without SELinux are not
vulnerable. (CVE-2021-23240).");

  script_tag(name:"affected", value:"'sudo' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.9.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-devel", rpm:"sudo-devel~1.9.5~1.mga7", rls:"MAGEIA7"))) {
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
