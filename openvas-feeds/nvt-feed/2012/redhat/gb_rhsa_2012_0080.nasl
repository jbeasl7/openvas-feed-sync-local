# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-February/msg00006.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870598");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-07-09 10:31:29 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-3659", "CVE-2011-3670", "CVE-2012-0442", "CVE-2012-0449");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2012:0080-01");
  script_name("RedHat Update for thunderbird RHSA-2012:0080-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"thunderbird on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  A use-after-free flaw was found in the way Thunderbird removed
  nsDOMAttribute child nodes. In certain circumstances, due to the premature
  notification of AttributeChildRemoved, a malicious script could possibly
  use this flaw to cause Thunderbird to crash or, potentially, execute
  arbitrary code with the privileges of the user running Thunderbird.
  (CVE-2011-3659)

  Several flaws were found in the processing of malformed content. An HTML
  mail message containing malicious content could cause Thunderbird to crash
  or, potentially, execute arbitrary code with the privileges of the user
  running Thunderbird. (CVE-2012-0442)

  A flaw was found in the way Thunderbird parsed certain Scalable Vector
  Graphics (SVG) image files that contained eXtensible Style Sheet Language
  Transformations (XSLT). An HTML mail message containing a malicious SVG
  image file could cause Thunderbird to crash or, potentially, execute
  arbitrary code with the privileges of the user running Thunderbird.
  (CVE-2012-0449)

  The same-origin policy in Thunderbird treated  http://example.com and
  http://[example.com] as interchangeable. A malicious script could possibly
  use this flaw to gain access to sensitive information (such as a client's
  IP and user e-mail address, or httpOnly cookies) that may be included in
  HTTP proxy error replies, generated in response to invalid URLs using
  square brackets. (CVE-2011-3670)

  Note: The CVE-2011-3659 and CVE-2011-3670 issues cannot be exploited by a
  specially-crafted HTML mail message as JavaScript is disabled by default
  for mail messages. It could be exploited another way in Thunderbird, for
  example, when viewing the full remote content of an RSS feed.

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Thunderbird 3.1.18. You can find a link to the Mozilla
  advisories in the References section of this erratum.

  All Thunderbird users should upgrade to these updated packages, which
  contain Thunderbird version 3.1.18, which corrects these issues. After
  installing the update, Thunderbird must be restarted for the changes to
  take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~3.1.18~1.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~3.1.18~1.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
