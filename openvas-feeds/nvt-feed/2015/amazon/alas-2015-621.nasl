# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120611");
  script_cve_id("CVE-2013-1752", "CVE-2014-4650", "CVE-2014-7185");
  script_tag(name:"creation_date", value:"2015-12-15 00:51:23 +0000 (Tue, 15 Dec 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 13:49:00 +0000 (Wed, 26 Feb 2020)");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-621)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-621");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-621.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python26' package(s) announced via the ALAS-2015-621 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow flaw was found in the way the buffer() function handled its offset and size arguments. An attacker able to control those arguments could use this flaw to disclose portions of the application memory or cause it to crash.

It was discovered that multiple Python standard library modules implementing network protocols (such as httplib or smtplib) failed to restrict sizes of server responses. A malicious server could cause a client using one of the affected modules to consume an excessive amount of memory.

It was discovered that the CGIHTTPServer module incorrectly handled URL encoded paths. A remote attacker could use this flaw to execute scripts outside of the cgi-bin directory, or disclose source of scripts in the cgi-bin directory.");

  script_tag(name:"affected", value:"'python26' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"python26", rpm:"python26~2.6.9~2.83.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python26-debuginfo", rpm:"python26-debuginfo~2.6.9~2.83.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python26-devel", rpm:"python26-devel~2.6.9~2.83.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python26-libs", rpm:"python26-libs~2.6.9~2.83.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python26-test", rpm:"python26-test~2.6.9~2.83.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python26-tools", rpm:"python26-tools~2.6.9~2.83.amzn1", rls:"AMAZON"))) {
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
