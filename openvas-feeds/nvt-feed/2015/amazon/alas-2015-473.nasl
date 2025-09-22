# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120286");
  script_cve_id("CVE-2015-0235");
  script_tag(name:"creation_date", value:"2015-09-08 11:22:42 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-473)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-473");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-473.html");
  script_xref(name:"URL", value:"https://aws.amazon.com/amazon-linux-ami/faqs/#lock");
  script_xref(name:"URL", value:"https://aws.amazon.com/amazon-linux-ami/faqs/#lock");
  script_xref(name:"URL", value:"https://aws.amazon.com/amazon-linux-ami/faqs/#lock");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the ALAS-2015-473 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer overflow was found in glibc's __nss_hostname_digits_dots() function, which is used by the gethostbyname() and gethostbyname2() glibc function calls. A remote attacker able to make an application call either of these functions could use this flaw to execute arbitrary code with the permissions of the user running the application.

<br/><h4>Special notes:</h4>

Because of the exceptional nature of this security event, we have backfilled our 2014.03 and 2013.09 Amazon Linux AMI repositories with new glibc packages that fix CVE-2015-0235.

For 2014.09 Amazon Linux AMIs, <i>glibc-2.17-55.93.amzn1</i> addresses the CVE. Running <i>yum clean all</i> followed by <i>yum update glibc</i> will install the fixed package, and you should reboot your instance after installing the update.

For Amazon Linux AMIs 'locked' to the 2014.03 repositories, the same <i>glibc-2.17-55.93.amzn1</i> addresses the CVE. Running <i>yum clean all</i> followed by <i>yum update glibc</i> will install the fixed package, and you should reboot your instance after installing the update.

For Amazon Linux AMIs 'locked' to the 2013.09 repositories, <i>glibc-2.12-1.149.49.amzn1</i> addresses the CVE. Running <i>yum clean all</i> followed by <i>yum update glibc</i> will install the fixed package, and you should reboot your instance after installing the update.

For Amazon Linux AMIs 'locked' to the 2013.03, 2012.09, 2012.03, or 2011.09 repositories, run <i>yum clean all</i> followed by <i>yum --releasever=2013.09 update glibc</i> to install the updated glibc package. You should reboot your instance after installing the update.

If you are using a pre-2011.09 Amazon Linux AMI, then you are using a version of the Amazon Linux AMI that was part of our public beta, and we encourage you to move to a newer version of the Amazon Linux AMI as soon as possible.");

  script_tag(name:"affected", value:"'glibc' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.17~55.93.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.17~55.93.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-debuginfo", rpm:"glibc-debuginfo~2.17~55.93.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-debuginfo-common", rpm:"glibc-debuginfo-common~2.17~55.93.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.17~55.93.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.17~55.93.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static", rpm:"glibc-static~2.17~55.93.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.17~55.93.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.17~55.93.amzn1", rls:"AMAZON"))) {
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
