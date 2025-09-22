# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0022");
  script_cve_id("CVE-2017-18018", "CVE-2018-17942");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-20 16:25:37 +0000 (Tue, 20 Nov 2018)");

  script_name("Mageia: Security Advisory (MGASA-2019-0022)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0022");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0022.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22495");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23825");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4ZP6L5HXDOVKYTM5ELLYE64H75MT4LZR/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/JK2ISMPYUEU3JS3L7AVXEHWCI56INCJJ/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'coreutils' package(s) announced via the MGASA-2019-0022 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in GNU Coreutils through 8.29 in chown-core.c. The
functions chown and chgrp do not prevent replacement of a plain file
with a symlink during use of the POSIX '-R -L' options, which allows
local users to modify the ownership of arbitrary files by leveraging a
race condition (CVE-2017-18018).

A flaw was found in Gnulib before 2018-09-23. The convert_to_decimal
function in vasnprintf.c has a heap-based buffer overflow because memory
is not allocated for a trailing '\0' character during %f processing
(CVE-2018-17942).");

  script_tag(name:"affected", value:"'coreutils' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"coreutils", rpm:"coreutils~8.25~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreutils-doc", rpm:"coreutils-doc~8.25~3.1.mga6", rls:"MAGEIA6"))) {
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
