# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-February/018408.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881145");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:22:04 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-3670", "CVE-2012-0442");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2012:0085");
  script_name("CentOS Update for thunderbird CESA-2012:0085 centos4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"thunderbird on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  A flaw was found in the processing of malformed content. An HTML mail
  message containing malicious content could cause Thunderbird to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Thunderbird. (CVE-2012-0442)

  The same-origin policy in Thunderbird treated http://example.com and http://[example.com]
  as interchangeable. A malicious script could possibly
  use this flaw to gain access to sensitive information (such as a client's
  IP and user e-mail address, or httpOnly cookies) that may be included in
  HTTP proxy error replies, generated in response to invalid URLs using
  square brackets. (CVE-2011-3670)

  Note: The CVE-2011-3670 issue cannot be exploited by a specially-crafted
  HTML mail message as JavaScript is disabled by default for mail messages.
  It could be exploited another way in Thunderbird, for example, when viewing
  the full remote content of an RSS feed.

  All Thunderbird users should upgrade to this updated package, which
  resolves these issues. All running instances of Thunderbird must be
  restarted for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~1.5.0.12~46.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
