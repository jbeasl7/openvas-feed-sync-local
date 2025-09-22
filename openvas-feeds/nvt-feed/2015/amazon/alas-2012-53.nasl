# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120414");
  script_cve_id("CVE-2012-1053", "CVE-2012-1054");
  script_tag(name:"creation_date", value:"2015-09-08 11:25:51 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2012-53)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2012-53");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2012-53.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'puppet' package(s) announced via the ALAS-2012-53 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Puppet 2.6.x before 2.6.14 and 2.7.x before 2.7.11, and Puppet Enterprise (PE) Users 1.0, 1.1, 1.2.x, 2.0.x before 2.0.3, when managing a user login file with the k5login resource type, allows local users to gain privileges via a symlink attack on .k5login.

The change_user method in the SUIDManager (lib/puppet/util/suidmanager.rb) in Puppet 2.6.x before 2.6.14 and 2.7.x before 2.7.11, and Puppet Enterprise (PE) Users 1.0, 1.1, 1.2.x, 2.0.x before 2.0.3 does not properly manage group privileges, which allows local users to gain privileges via vectors related to (1) the change_user not dropping supplementary groups in certain conditions, (2) changes to the eguid without associated changes to the egid, or (3) the addition of the real gid to supplementary groups.");

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

  if(!isnull(res = isrpmvuln(pkg:"puppet", rpm:"puppet~2.6.14~1.5.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"puppet-debuginfo", rpm:"puppet-debuginfo~2.6.14~1.5.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"puppet-server", rpm:"puppet-server~2.6.14~1.5.amzn1", rls:"AMAZON"))) {
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
