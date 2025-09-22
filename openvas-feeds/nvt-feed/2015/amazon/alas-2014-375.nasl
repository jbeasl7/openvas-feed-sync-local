# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120574");
  script_cve_id("CVE-2014-0240", "CVE-2014-0242");
  script_tag(name:"creation_date", value:"2015-09-08 11:29:52 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-17 17:22:00 +0000 (Tue, 17 Dec 2019)");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-375)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-375");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-375.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod24_wsgi' package(s) announced via the ALAS-2014-375 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that mod_wsgi did not properly drop privileges if the call to setuid() failed. If mod_wsgi was set up to allow unprivileged users to run WSGI applications, a local user able to run a WSGI application could possibly use this flaw to escalate their privileges on the system. Note: mod_wsgi is not intended to provide privilege separation for WSGI applications. Systems relying on mod_wsgi to limit or sandbox the privileges of mod_wsgi applications should migrate to a different solution with proper privilege separation.

mod_wsgi allows you to host Python applications on the Apache HTTP Server. It was found that a remote attacker could leak portions of a mod_wsgi application's memory via the Content-Type header.");

  script_tag(name:"affected", value:"'mod24_wsgi' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"mod24_wsgi", rpm:"mod24_wsgi~3.5~1.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_wsgi-debuginfo", rpm:"mod24_wsgi-debuginfo~3.5~1.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_wsgi-py27", rpm:"mod24_wsgi-py27~3.5~1.17.amzn1", rls:"AMAZON"))) {
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
