# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69326");
  script_cve_id("CVE-2011-0700", "CVE-2011-0701");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2190-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2190-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2190-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2190");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-2190-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two XSS bugs and one potential information disclosure issue were discovered in WordPress, a weblog manager. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2011-0700

Input passed via the post title when performing a Quick Edit or Bulk Edit action and via the post_status, comment_status, and ping_status parameters is not properly sanitised before being used. Certain input passed via tags in the tags meta-box is not properly sanitised before being returned to the user.

CVE-2011-0701

WordPress incorrectly enforces user access restrictions when accessing posts via the media uploader and can be exploited to disclose the contents of e.g. private or draft posts.

The oldstable distribution (lenny) is not affected by these problems.

For the stable distribution (squeeze), these problems have been fixed in version 3.0.5+dfsg-0+squeeze1.

For the testing distribution (wheezy), and the unstable distribution (sid), these problems have been fixed in version 3.0.5+dfsg-1.

We recommend that you upgrade your wordpress packages.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"3.0.5+dfsg-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.0.5+dfsg-0+squeeze1", rls:"DEB6"))) {
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
