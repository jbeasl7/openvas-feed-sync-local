# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0330");
  script_cve_id("CVE-2013-4251");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-08 18:51:23 +0000 (Fri, 08 Nov 2019)");

  script_name("Mageia: Security Advisory (MGASA-2013-0330)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0330");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0330.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11555");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2013-October/119771.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-scipy' package(s) announced via the MGASA-2013-0330 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python-scipy package fixes security vulnerability:

scipy.weave will use /tmp/[username] as persistent storage (cache), but it
does not check whether or not this directory already exists, does not check
whether it is a directory or a symlink, and also does not verify permissions
or ownership, which could allow someone to place code in this directory that
would be executed as the user running scipy.weave (CVE-2013-4251).

The update also adds some missing dependencies.");

  script_tag(name:"affected", value:"'python-scipy' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"python-scipy", rpm:"python-scipy~0.9.0~3.4.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"python-scipy", rpm:"python-scipy~0.9.0~7.3.mga3", rls:"MAGEIA3"))) {
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
