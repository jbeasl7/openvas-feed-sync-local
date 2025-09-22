# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881930");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2014-05-05 11:19:05 +0530 (Mon, 05 May 2014)");
  script_cve_id("CVE-2014-1518", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1529",
                "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-07 19:26:00 +0000 (Fri, 07 Aug 2020)");
  script_name("CentOS Update for firefox CESA-2014:0448 centos5");

  script_tag(name:"affected", value:"firefox on CentOS 5");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2014-1518, CVE-2014-1524, CVE-2014-1529, CVE-2014-1531)

A use-after-free flaw was found in the way Firefox resolved hosts in
certain circumstances. An attacker could use this flaw to crash Firefox or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2014-1532)

An out-of-bounds read flaw was found in the way Firefox decoded JPEG
images. Loading a web page containing a specially crafted JPEG image could
cause Firefox to crash. (CVE-2014-1523)

A flaw was found in the way Firefox handled browser navigations through
history. An attacker could possibly use this flaw to cause the address bar
of the browser to display a web page name while loading content from an
entirely different web page, which could allow for cross-site scripting
(XSS) attacks. (CVE-2014-1530)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Bobby Holley, Carsten Book, Christoph Diehl, Gary
Kwong, Jan de Mooij, Jesse Ruderman, Nathan Froyd, Christian Holler,
Abhishek Arya, Mariusz Mlynski, moz_bug_r_a4, Nils, Tyson Smith, and Jesse
Schwartzentrube as the original reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla security
advisories for Firefox 24.5.0 ESR. You can find a link to the Mozilla
advisories in the References section of this erratum.

All Firefox users should upgrade to this updated package, which contains
Firefox version 24.5.0 ESR, which corrects these issues. After installing
the update, Firefox must be restarted for the changes to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0448");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-April/020274.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~24.5.0~1.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
