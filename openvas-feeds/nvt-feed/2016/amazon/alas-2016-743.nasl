# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120732");
  script_cve_id("CVE-2015-8916", "CVE-2015-8917", "CVE-2015-8919", "CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8922", "CVE-2015-8923", "CVE-2015-8924", "CVE-2015-8925", "CVE-2015-8926", "CVE-2015-8928", "CVE-2015-8930", "CVE-2015-8931", "CVE-2015-8932", "CVE-2015-8934", "CVE-2016-1541", "CVE-2016-4300", "CVE-2016-4302", "CVE-2016-4809", "CVE-2016-5418", "CVE-2016-5844", "CVE-2016-6250", "CVE-2016-7166");
  script_tag(name:"creation_date", value:"2016-10-26 12:38:23 +0000 (Wed, 26 Oct 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-743)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-743");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-743.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the ALAS-2016-743 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way libarchive handled hardlink archive entries of non-zero size. Combined with flaws in libarchive's file system sandboxing, this issue could cause an application using libarchive to overwrite arbitrary files with arbitrary data from the archive. (CVE-2016-5418)

Multiple out-of-bounds write flaws were found in libarchive. Specially crafted ZIP, 7ZIP, or RAR files could cause a heap overflow, potentially allowing code execution in the context of the application using libarchive. (CVE-2016-1541, CVE-2016-4300, CVE-2016-4302)

Multiple out-of-bounds read flaws were found in libarchive. Specially crafted LZA/LZH, AR, MTREE, ZIP, TAR, or RAR files could cause the application to read data out of bounds, potentially disclosing a small amount of application memory, or causing an application crash. (CVE-2015-8919, CVE-2015-8920, CVE-2015-8921, CVE-2015-8923, CVE-2015-8924, CVE-2015-8925, CVE-2015-8926, CVE-2015-8928, CVE-2015-8934)

Multiple NULL pointer dereference flaws were found in libarchive. Specially crafted RAR, CAB, or 7ZIP files could cause an application using libarchive to crash. (CVE-2015-8916, CVE-2015-8917, CVE-2015-8922)

Multiple infinite loop / resource exhaustion flaws were found in libarchive. Specially crafted GZIP or ISO files could cause the application to consume an excessive amount of resources, eventually leading to a crash on memory exhaustion. (CVE-2016-7166, CVE-2015-8930)

A denial of service vulnerability was found in libarchive. A specially crafted CPIO archive containing a symbolic link to a large target path could cause memory allocation to fail, causing an application using libarchive that attempted to view or extract such archive to crash. (CVE-2016-4809)

An integer overflow flaw, leading to a buffer overflow, was found in libarchive's construction of ISO9660 volumes. Attempting to create an ISO9660 volume with 2 GB or 4 GB file names could cause the application to attempt to allocate 20 GB of memory. If this were to succeed, it could lead to an out of bounds write on the heap and potential code execution. (CVE-2016-6250)

Multiple instances of undefined behavior due to arithmetic overflow were found in libarchive. Specially crafted MTREE archives, Compress streams, or ISO9660 volumes could potentially cause the application to fail to read the archive, or to crash. (CVE-2015-8931, CVE-2015-8932, CVE-2016-5844)");

  script_tag(name:"affected", value:"'libarchive' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"bsdcpio", rpm:"bsdcpio~3.1.2~10.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdtar", rpm:"bsdtar~3.1.2~10.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive", rpm:"libarchive~3.1.2~10.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-debuginfo", rpm:"libarchive-debuginfo~3.1.2~10.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-devel", rpm:"libarchive-devel~3.1.2~10.11.amzn1", rls:"AMAZON"))) {
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
