# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120610");
  script_cve_id("CVE-2014-8484", "CVE-2014-8485", "CVE-2014-8501", "CVE-2014-8502", "CVE-2014-8503", "CVE-2014-8504", "CVE-2014-8737", "CVE-2014-8738");
  script_tag(name:"creation_date", value:"2015-12-15 00:51:23 +0000 (Tue, 15 Dec 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-620)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-620");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-620.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the ALAS-2015-620 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A directory traversal flaw was found in the strip and objcopy utilities. A specially crafted file could cause strip or objdump to overwrite an arbitrary file writable by the user running either of these utilities.

A buffer overflow flaw was found in the way various binutils utilities processed certain files. If a user were tricked into processing a specially crafted file, it could cause the utility used to process that file to crash or, potentially, execute arbitrary code with the privileges of the user running that utility.

An integer overflow flaw was found in the way the strings utility processed certain files. If a user were tricked into running the strings utility on a specially crafted file, it could cause the strings executable to crash.

A stack-based buffer overflow flaw was found in the SREC parser of the libbfd library. A specially crafted file could cause an application using the libbfd library to crash or, potentially, execute arbitrary code with the privileges of the user running that application.

A heap-based buffer overflow flaw was found in the way certain binutils utilities processed archive files. If a user were tricked into processing a specially crafted archive file, it could cause the utility used to process that archive to crash or, potentially, execute arbitrary code with the privileges of the user running that utility.

A stack-based buffer overflow flaw was found in the way various binutils utilities processed certain files. If a user were tricked into processing a specially crafted file, it could cause the utility used to process that file to crash or, potentially, execute arbitrary code with the privileges of the user running that utility.

A stack-based buffer overflow flaw was found in the way objdump processed IHEX files. A specially crafted IHEX file could cause objdump to crash or, potentially, execute arbitrary code with the privileges of the user running objdump.

It was found that the fix for the CVE-2014-8485 issue was incomplete: a heap-based buffer overflow in the objdump utility could cause it to crash or, potentially, execute arbitrary code with the privileges of the user running objdump when processing specially crafted files.");

  script_tag(name:"affected", value:"'binutils' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.23.52.0.1~55.65.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.23.52.0.1~55.65.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.23.52.0.1~55.65.amzn1", rls:"AMAZON"))) {
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
