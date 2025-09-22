# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120078");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_tag(name:"creation_date", value:"2015-09-08 11:16:55 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 16:47:58 +0000 (Wed, 24 Jul 2024)");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-419)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-419");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-419.html");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-418.html");
  script_xref(name:"URL", value:"https://aws.amazon.com/amazon-linux-ami/faqs/#lock");
  script_xref(name:"URL", value:"https://aws.amazon.com/amazon-linux-ami/faqs/#lock");
  script_xref(name:"URL", value:"https://aws.amazon.com/amazon-linux-ami/faqs/#lock");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bash' package(s) announced via the ALAS-2014-419 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNU Bash through 4.3 bash43-025 processes trailing strings after certain malformed function definitions in the values of environment variables, which allows remote attackers to write to files or possibly have unknown other impact via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution.

NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-6271 and this bulletin is a follow-up to ALAS-2014-418.

It was discovered that the fixed-sized redir_stack could be forced to overflow in the Bash parser, resulting in memory corruption, and possibly leading to arbitrary code execution when evaluating untrusted input that would not otherwise be run as code.

An off-by-one error was discovered in the way Bash was handling deeply nested flow control constructs. Depending on the layout of the .bss segment, this could allow arbitrary execution of code that would not otherwise be executed by Bash.

<br/><h4>Special notes:</h4>

Because of the exceptional nature of this security event, we have backfilled our 2014.03, 2013.09, and 2013.03 Amazon Linux AMI repositories with new bash packages that also fix both CVE-2014-7169 and CVE-2014-6271.

For 2014.09 Amazon Linux AMIs, <i>bash-4.1.2-15.21.amzn1</i> addresses both CVEs. Running <i>yum clean all</i> followed by <i>yum update bash</i> will install the fixed package.

For Amazon Linux AMIs 'locked' to the 2014.03 repositories, <i>bash-4.1.2-15.21.amzn1</i> also addresses both CVEs. Running <i>yum clean all</i> followed by <i>yum update bash</i> will install the fixed package.

For Amazon Linux AMIs 'locked' to the 2013.09 or 2013.03 repositories, <i>bash-4.1.2-15.18.22.amzn1</i> addresses both CVEs. Running <i>yum clean all</i> followed by <i>yum update bash</i> will install the fixed package.

For Amazon Linux AMIs 'locked' to the 2012.09, 2012.03, or 2011.09 repositories, run <i>yum clean all</i> followed by <i>yum --releasever=2013.03 update bash</i> to install only the updated bash package.

If you are using a pre-2011.09 Amazon Linux AMI, then you are using a version of the Amazon Linux AMI that was part of our public beta, and we encourage you to move to a newer version of the Amazon Linux AMI as soon as possible.");

  script_tag(name:"affected", value:"'bash' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"bash", rpm:"bash~4.1.2~15.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bash-debuginfo", rpm:"bash-debuginfo~4.1.2~15.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bash-doc", rpm:"bash-doc~4.1.2~15.21.amzn1", rls:"AMAZON"))) {
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
