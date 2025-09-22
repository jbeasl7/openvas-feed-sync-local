# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120688");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-3714", "CVE-2016-3715", "CVE-2016-3716", "CVE-2016-3717", "CVE-2016-3718");
  script_tag(name:"creation_date", value:"2016-10-26 12:38:07 +0000 (Wed, 26 Oct 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-11 11:11:26 +0000 (Wed, 11 Sep 2024)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-699)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-699");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-699.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the ALAS-2016-699 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ImageMagick did not properly sanitize certain input before passing it to the delegate functionality. A remote attacker could create a specially crafted image that, when processed by an application using ImageMagick or an unsuspecting user using the ImageMagick utilities, would lead to arbitrary execution of shell commands with the privileges of the user running the application. (CVE-2016-3714)

It was discovered that certain ImageMagick coders and pseudo-protocols did not properly prevent security sensitive operations when processing specially crafted images. A remote attacker could create a specially crafted image that, when processed by an application using ImageMagick or an unsuspecting user using the ImageMagick utilities, would allow the attacker to disclose the contents of arbitrary files. (CVE-2016-3715, CVE-2016-3716, CVE-2016-3717)

A server-side request forgery flaw was discovered in the way ImageMagick processed certain images. A remote attacker could exploit this flaw to mislead an application using ImageMagick or an unsuspecting user using the ImageMagick utilities into, for example, performing HTTP(S) requests or opening FTP sessions via specially crafted images. (CVE-2016-3718)

Note: This update contains an updated /etc/ImageMagick/policy.xml file that disables the EPHEMERAL, HTTPS, HTTP, URL, FTP, MVG, MSL, TEXT, and LABEL coders. If you experience any problems after the update, it may be necessary to manually adjust the policy.xml file to match your requirements. Please take additional precautions to ensure that your applications using the ImageMagick library do not process malicious or untrusted files before doing so.");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.7.8.9~13.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-c++", rpm:"ImageMagick-c++~6.7.8.9~13.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-c++-devel", rpm:"ImageMagick-c++-devel~6.7.8.9~13.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.7.8.9~13.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.7.8.9~13.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~6.7.8.9~13.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-perl", rpm:"ImageMagick-perl~6.7.8.9~13.19.amzn1", rls:"AMAZON"))) {
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
