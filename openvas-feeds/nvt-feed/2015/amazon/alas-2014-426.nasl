# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120188");
  script_cve_id("CVE-2014-3566");
  script_tag(name:"creation_date", value:"2015-09-08 11:19:31 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-16 12:15:00 +0000 (Wed, 16 Jun 2021)");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-426)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-426");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-426.html");
  script_xref(name:"URL", value:"https://aws.amazon.com/amazon-linux-ami/faqs/#lock");
  script_xref(name:"URL", value:"https://aws.amazon.com/amazon-linux-ami/faqs/#lock");
  script_xref(name:"URL", value:"http://googleonlinesecurity.blogspot.com/2014/10/this-poodle-bites-exploiting-ssl-30.html");
  script_xref(name:"URL", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the ALAS-2014-426 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bodo Moller, Thai Duong and Krzysztof Kotowicz of Google discovered a flaw in the design of SSL version 3.0 that would allow an attacker to calculate the plaintext of secure connections, allowing, for example, secure HTTP cookies to be stolen.

[link moved to references]
[link moved to references]

<br/><h4>Special notes:</h4>

We have backfilled our 2014.03, 2013.09, and 2013.03 Amazon Linux AMI repositories with updated openssl packages that fix CVE-2014-3566.

For 2014.09 Amazon Linux AMIs, <i>openssl-1.0.1i-1.79.amzn1</i> addresses this CVE. Running <i>yum clean all</i> followed by <i>yum update openssl</i> will install the fixed package.

For Amazon Linux AMIs 'locked' to the 2014.03 repositories, <i>openssl-1.0.1i-1.79.amzn1</i> also addresses this CVE. Running <i>yum clean all</i> followed by <i>yum update openssl</i> will install the fixed package.

For Amazon Linux AMIs 'locked' to the 2013.09 or 2013.03 repositories, <i>openssl-1.0.1e-4.60.amzn1</i> addresses this CVE. Running <i>yum clean all</i> followed by <i>yum update openssl</i> will install the fixed package.

If you are using a pre-2013.03 Amazon Linux AMI, we encourage you to move to a newer version of the Amazon Linux AMI as soon as possible.");

  script_tag(name:"affected", value:"'openssl' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1i~1.79.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.1i~1.79.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1i~1.79.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1i~1.79.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1i~1.79.amzn1", rls:"AMAZON"))) {
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
