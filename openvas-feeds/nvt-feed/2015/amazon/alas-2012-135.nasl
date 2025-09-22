# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120334");
  script_cve_id("CVE-2012-3864", "CVE-2012-3865", "CVE-2012-3866", "CVE-2012-3867");
  script_tag(name:"creation_date", value:"2015-09-08 11:23:48 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Amazon Linux: Security Advisory (ALAS-2012-135)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2012-135");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2012-135.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'puppet' package(s) announced via the ALAS-2012-135 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Directory traversal vulnerability in lib/puppet/reports/store.rb in Puppet before 2.6.17 and 2.7.x before 2.7.18, and Puppet Enterprise before 2.5.2, when Delete is enabled in auth.conf, allows remote authenticated users to delete arbitrary files on the puppet master server via a .. (dot dot) in a node name.

Puppet before 2.6.17 and 2.7.x before 2.7.18, and Puppet Enterprise before 2.5.2, allows remote authenticated users to read arbitrary files on the puppet master server by leveraging an arbitrary user's certificate and private key in a GET request.

lib/puppet/ssl/certificate_authority.rb in Puppet before 2.6.17 and 2.7.x before 2.7.18, and Puppet Enterprise before 2.5.2, does not properly restrict the characters in the Common Name field of a Certificate Signing Request (CSR), which makes it easier for user-assisted remote attackers to trick administrators into signing a crafted agent certificate via ANSI control sequences.

lib/puppet/defaults.rb in Puppet 2.7.x before 2.7.18, and Puppet Enterprise before 2.5.2, uses 0644 permissions for last_run_report.yaml, which allows local users to obtain sensitive configuration information by leveraging access to the puppet master server to read this file.");

  script_tag(name:"affected", value:"'puppet' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"puppet", rpm:"puppet~2.7.18~1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"puppet-debuginfo", rpm:"puppet-debuginfo~2.7.18~1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"puppet-server", rpm:"puppet-server~2.7.18~1.9.amzn1", rls:"AMAZON"))) {
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
