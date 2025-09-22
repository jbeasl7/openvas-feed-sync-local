# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120713");
  script_cve_id("CVE-2016-0772", "CVE-2016-5636", "CVE-2016-5699");
  script_tag(name:"creation_date", value:"2016-10-26 12:38:16 +0000 (Wed, 26 Oct 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-09 11:29:00 +0000 (Sat, 09 Feb 2019)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-724)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-724");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-724.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python26, python27, python34' package(s) announced via the ALAS-2016-724 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that Python's httplib library (used urllib, urllib2 and others) did not properly check HTTP header input in HTTPConnection.putheader(). An attacker could use this flow to inject additional headers in a Python application that allows user provided header name or values. (CVE-2016-5699)

It was found that Python's smtplib library did not return an exception if StartTLS fails to establish correctly in the SMTP.starttls() function. An attacker with ability to launch an active man in the middle attack could strip out the STARTTLS command without generating an exception on the python SMTP client application, preventing the establishment of the TLS layer. (CVE-2016-0772)

A vulnerability was discovered in Python, in the built-in zipimporter. A specially crafted zip file placed in a module path such that it would be loaded by a later 'import' statement could cause a heap overflow, leading to arbitrary code execution. (CVE-2016-5636)");

  script_tag(name:"affected", value:"'python26, python27, python34' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"python26", rpm:"python26~2.6.9~2.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python26-debuginfo", rpm:"python26-debuginfo~2.6.9~2.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python26-devel", rpm:"python26-devel~2.6.9~2.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python26-libs", rpm:"python26-libs~2.6.9~2.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python26-test", rpm:"python26-test~2.6.9~2.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python26-tools", rpm:"python26-tools~2.6.9~2.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27", rpm:"python27~2.7.10~4.122.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-debuginfo", rpm:"python27-debuginfo~2.7.10~4.122.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-devel", rpm:"python27-devel~2.7.10~4.122.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-libs", rpm:"python27-libs~2.7.10~4.122.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-test", rpm:"python27-test~2.7.10~4.122.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-tools", rpm:"python27-tools~2.7.10~4.122.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python34", rpm:"python34~3.4.3~1.32.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python34-debuginfo", rpm:"python34-debuginfo~3.4.3~1.32.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python34-devel", rpm:"python34-devel~3.4.3~1.32.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python34-libs", rpm:"python34-libs~3.4.3~1.32.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python34-test", rpm:"python34-test~3.4.3~1.32.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python34-tools", rpm:"python34-tools~3.4.3~1.32.amzn1", rls:"AMAZON"))) {
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
