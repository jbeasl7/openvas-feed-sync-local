# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702830");
  script_cve_id("CVE-2013-4492");
  script_tag(name:"creation_date", value:"2013-12-29 23:00:00 +0000 (Sun, 29 Dec 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2830-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2830-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2830-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2830");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-i18n' package(s) announced via the DSA-2830-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Peter McLarnan discovered that the internationalization component of Ruby on Rails does not properly encode parameters in generated HTML code, resulting in a cross-site scripting vulnerability. This update corrects the underlying vulnerability in the i18n gem, as provided by the ruby-i18n package.

The oldstable distribution (squeeze) is not affected by this problem, the libi18n-ruby package does not contain the vulnerable code.

For the stable distribution (wheezy), this problem has been fixed in version 0.6.0-3+deb7u1.

For the unstable distribution (sid), this problem has been fixed in version 0.6.9-1.

We recommend that you upgrade your ruby-i18n packages.");

  script_tag(name:"affected", value:"'ruby-i18n' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libi18n-ruby", ver:"0.6.0-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libi18n-ruby1.8", ver:"0.6.0-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libi18n-ruby1.9.1", ver:"0.6.0-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-i18n", ver:"0.6.0-3+deb7u1", rls:"DEB7"))) {
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
