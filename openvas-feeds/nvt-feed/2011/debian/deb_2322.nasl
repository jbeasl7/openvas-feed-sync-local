# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70411");
  script_cve_id("CVE-2010-4567", "CVE-2010-4568", "CVE-2010-4572", "CVE-2011-0046", "CVE-2011-0048", "CVE-2011-2379", "CVE-2011-2380", "CVE-2011-2381", "CVE-2011-2978", "CVE-2011-2979");
  script_tag(name:"creation_date", value:"2011-10-16 21:01:53 +0000 (Sun, 16 Oct 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2322-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2322-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2322-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2322");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bugzilla' package(s) announced via the DSA-2322-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Bugzilla, a web-based bug tracking system.

CVE-2010-4572

By inserting particular strings into certain URLs, it was possible to inject both headers and content to any browser.

CVE-2010-4567, CVE-2011-0048 Bugzilla has a URL field that can contain several types of URL, including javascript: and data: URLs. However, it does not make javascript: and data: URLs into clickable links, to protect against cross-site scripting attacks or other attacks. It was possible to bypass this protection by adding spaces into the URL in places that Bugzilla did not expect them. Also, javascript: and data: links were always shown as clickable to logged-out users.

CVE-2010-4568

It was possible for a user to gain unauthorized access to any Bugzilla account in a very short amount of time (short enough that the attack is highly effective).

CVE-2011-0046

Various pages were vulnerable to Cross-Site Request Forgery attacks. Most of these issues are not as serious as previous CSRF vulnerabilities.

CVE-2011-2978

When a user changes his email address, Bugzilla trusts a user-modifiable field for obtaining the current e-mail address to send a confirmation message to. If an attacker has access to the session of another user (for example, if that user left their browser window open in a public place), the attacker could alter this field to cause the email-change notification to go to their own address. This means that the user would not be notified that his account had its email address changed by the attacker.

CVE-2011-2381

For flagmails only, attachment descriptions with a newline in them could lead to the injection of crafted headers in email notifications when an attachment flag is edited.

CVE-2011-2379

Bugzilla uses an alternate host for attachments when viewing them in raw format to prevent cross-site scripting attacks. This alternate host is now also used when viewing patches in Raw Unified mode because Internet Explorer 8 and older, and Safari before 5.0.6 do content sniffing, which could lead to the execution of malicious code.

CVE-2011-2380, CVE-2011-2979 Normally, a group name is confidential and is only visible to members of the group, and to non-members if the group is used in bugs. By crafting the URL when creating or editing a bug, it was possible to guess if a group existed or not, even for groups which weren't used in bugs and so which were supposed to remain confidential.

For the oldstable distribution (lenny), it has not been practical to backport patches to fix these bugs. Users of bugzilla on lenny are strongly advised to upgrade to the version in the squeeze distribution.

For the stable distribution (squeeze), these problems have been fixed in version 3.6.2.0-4.4.

For the testing distribution (wheezy) and the unstable distribution (sid), the bugzilla packages have been removed.

We recommend that you upgrade your bugzilla packages.");

  script_tag(name:"affected", value:"'bugzilla' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"bugzilla3", ver:"3.6.2.0-4.4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bugzilla3-doc", ver:"3.6.2.0-4.4", rls:"DEB6"))) {
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
