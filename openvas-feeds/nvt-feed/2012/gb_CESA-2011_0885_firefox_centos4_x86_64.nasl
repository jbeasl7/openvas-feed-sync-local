# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-August/017680.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881317");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:21:56 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2362", "CVE-2011-2363",
                "CVE-2011-2364", "CVE-2011-2365", "CVE-2011-2371", "CVE-2011-2373",
                "CVE-2011-2374", "CVE-2011-2375", "CVE-2011-2376", "CVE-2011-2377");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:0885");
  script_name("CentOS Update for firefox CESA-2011:0885 centos4 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"firefox on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  A flaw was found in the way Firefox handled malformed JPEG images. A
  website containing a malicious JPEG image could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2011-2377)

  Multiple dangling pointer flaws were found in Firefox. A web page
  containing malicious content could cause Firefox to crash or, potentially,
  execute arbitrary code with the privileges of the user running Firefox.
  (CVE-2011-0083, CVE-2011-0085, CVE-2011-2363)

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2011-2364, CVE-2011-2365, CVE-2011-2374, CVE-2011-2375,
  CVE-2011-2376)

  An integer overflow flaw was found in the way Firefox handled JavaScript
  Array objects. A website containing malicious JavaScript could cause
  Firefox to execute that JavaScript with the privileges of the user running
  Firefox. (CVE-2011-2371)

  A use-after-free flaw was found in the way Firefox handled malformed
  JavaScript. A website containing malicious JavaScript could cause Firefox
  to execute that JavaScript with the privileges of the user running Firefox.
  (CVE-2011-2373)

  It was found that Firefox could treat two separate cookies as
  interchangeable if both were for the same domain name but one of those
  domain names had a trailing '.' character. This violates the same-origin
  policy and could possibly lead to data being leaked to the wrong domain.
  (CVE-2011-2362)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.6.18. You can find a link to the Mozilla
  advisories in the References section of this erratum.

  This update also fixes the following bug:

  * With previous versions of Firefox on Red Hat Enterprise Linux 5, the
  'background-repeat' CSS (Cascading Style Sheets) property did not work
  (such images were not displayed and repeated as expected). (BZ#698313)

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.6.18, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.6.18~2.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
