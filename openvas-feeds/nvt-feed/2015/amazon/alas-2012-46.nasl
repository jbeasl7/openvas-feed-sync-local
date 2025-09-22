# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120253");
  script_cve_id("CVE-2011-3607", "CVE-2011-3639", "CVE-2012-0031", "CVE-2012-0053");
  script_tag(name:"creation_date", value:"2015-09-08 11:21:35 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2012-46)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2012-46");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2012-46.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd' package(s) announced via the ALAS-2012-46 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the fix for CVE-2011-3368 did not completely address the problem. An attacker could bypass the fix and make a reverse proxy connect to an arbitrary server not directly accessible to the attacker by sending an HTTP version 0.9 request, or by using a specially-crafted URI. (CVE-2011-3639, CVE-2011-4317)

The httpd server included the full HTTP header line in the default error page generated when receiving an excessively long or malformed header. Malicious JavaScript running in the server's domain context could use this flaw to gain access to httpOnly cookies. (CVE-2012-0053)

An integer overflow flaw, leading to a heap-based buffer overflow, was found in the way httpd performed substitutions in regular expressions. An attacker able to set certain httpd settings, such as a user permitted to override the httpd configuration for a specific directory using a '.htaccess' file, could use this flaw to crash the httpd child process or, possibly, execute arbitrary code with the privileges of the 'apache' user. (CVE-2011-3607)

A flaw was found in the way httpd handled child process status information. A malicious program running with httpd child process privileges (such as a PHP or CGI script) could use this flaw to cause the parent httpd process to crash during httpd service shutdown. (CVE-2012-0031)");

  script_tag(name:"affected", value:"'httpd' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.22~1.23.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.2.22~1.23.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.22~1.23.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.22~1.23.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.2.22~1.23.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.22~1.23.amzn1", rls:"AMAZON"))) {
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
