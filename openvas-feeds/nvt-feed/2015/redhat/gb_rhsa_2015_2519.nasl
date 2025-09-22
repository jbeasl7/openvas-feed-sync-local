# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871510");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-11-27 06:15:16 +0100 (Fri, 27 Nov 2015)");
  script_cve_id("CVE-2015-4513", "CVE-2015-7189", "CVE-2015-7193", "CVE-2015-7197",
                "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for thunderbird RHSA-2015:2519-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail
and newsgroup client.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2015-4513, CVE-2015-7189, CVE-2015-7197, CVE-2015-7198,
CVE-2015-7199, CVE-2015-7200)

A same-origin policy bypass flaw was found in the way Thunderbird handled
certain cross-origin resource sharing (CORS) requests. A web page
containing malicious content could cause Thunderbird to disclose sensitive
information. (CVE-2015-7193)

Note: All of the above issues cannot be exploited by a specially crafted
HTML mail message because JavaScript is disabled by default for mail
messages. However, they could be exploited in other ways in Thunderbird
(for example, by viewing the full remote content of an RSS feed).

Red Hat would like to thank the Mozilla project for reporting this issue.
Upstream acknowledges Christian Holler, David Major, Jesse Ruderman, Tyson
Smith, Boris Zbarsky, Randell Jesup, Olli Pettay, Karl Tomlinson, Jeff
Walden, Gary Kwong, Looben Yang, Shinto K Anto, Ronald Crane, and Ehsan
Akhgari as the original reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla security
advisories for Thunderbird 38.4.0. You can find a link to the Mozilla
advisories in the References section of this erratum.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 38.4.0, which corrects these issues. After
installing the update, Thunderbird must be restarted for the changes to
take effect.");
  script_tag(name:"affected", value:"thunderbird on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:2519-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00067.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~38.4.0~1.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~38.4.0~1.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
