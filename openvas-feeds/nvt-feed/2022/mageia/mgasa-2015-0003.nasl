# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0003");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0003)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0003");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0003.html");
  script_xref(name:"URL", value:"http://www.privoxy.org/announce.txt");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14892");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'privoxy' package(s) announced via the MGASA-2015-0003 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated privoxy packages fix security issues:

A memory leak occurred in privoxy 3.0.21 compiled with IPv6 support when
rejecting client connections due to the socket limit being reached.
(CID 66382)

A use-after-free bug was found in privoxy 3.0.21 and two additional
potential use-after-free issues were detected by Coverity scan. (CID 66394,
CID 66376, CID 66391)

Also fixed is a file descriptor leak in an error path in jbsockets.c.
(CID 66368)");

  script_tag(name:"affected", value:"'privoxy' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"privoxy", rpm:"privoxy~3.0.21~2.2.mga4", rls:"MAGEIA4"))) {
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
