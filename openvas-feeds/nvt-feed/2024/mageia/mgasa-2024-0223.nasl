# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0223");
  script_cve_id("CVE-2024-5742");
  script_tag(name:"creation_date", value:"2024-06-17 04:12:21 +0000 (Mon, 17 Jun 2024)");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-24 15:39:46 +0000 (Tue, 24 Sep 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0223)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0223");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0223.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33297");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/VCJGQ6SCOSZGXAPYA7GYUT3M6ZPBLO5V/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nano' package(s) announced via the MGASA-2024-0223 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in GNU Nano that allows a possible privilege
escalation through an insecure temporary file. If Nano is killed while
editing, a file it saves to an emergency file with the permissions of
the running user provides a window of opportunity for attackers to
escalate privileges through a malicious symlink. (CVE-2024-5742)");

  script_tag(name:"affected", value:"'nano' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"nano", rpm:"nano~7.2~1.1.mga9", rls:"MAGEIA9"))) {
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
