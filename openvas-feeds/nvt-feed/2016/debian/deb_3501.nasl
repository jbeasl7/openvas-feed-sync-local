# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703501");
  script_cve_id("CVE-2016-2381");
  script_tag(name:"creation_date", value:"2016-03-08 07:07:36 +0000 (Tue, 08 Mar 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-12 17:12:46 +0000 (Tue, 12 Apr 2016)");

  script_name("Debian: Security Advisory (DSA-3501-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3501-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3501-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3501");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'perl' package(s) announced via the DSA-3501-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stephane Chazelas discovered a bug in the environment handling in Perl. Perl provides a Perl-space hash variable, %ENV, in which environment variables can be looked up. If a variable appears twice in envp, only the last value would appear in %ENV, but getenv would return the first. Perl's taint security mechanism would be applied to the value in %ENV, but not to the other rest of the environment. This could result in an ambiguous environment causing environment variables to be propagated to subprocesses, despite the protections supposedly offered by taint checking.

With this update Perl changes the behavior to match the following:

%ENV is populated with the first environment variable, as getenv would return.

Duplicate environment entries are removed.

For the oldstable distribution (wheezy), this problem has been fixed in version 5.14.2-21+deb7u3.

For the stable distribution (jessie), this problem has been fixed in version 5.20.2-3+deb8u4.

For the unstable distribution (sid), this problem will be fixed in version 5.22.1-8.

We recommend that you upgrade your perl packages.");

  script_tag(name:"affected", value:"'perl' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libcgi-fast-perl", ver:"5.14.2-21+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libperl-dev", ver:"5.14.2-21+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libperl5.14", ver:"5.14.2-21+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl", ver:"5.14.2-21+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-base", ver:"5.14.2-21+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-debug", ver:"5.14.2-21+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-doc", ver:"5.14.2-21+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-modules", ver:"5.14.2-21+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libperl-dev", ver:"5.20.2-3+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libperl5.20", ver:"5.20.2-3+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl", ver:"5.20.2-3+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-base", ver:"5.20.2-3+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-debug", ver:"5.20.2-3+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-doc", ver:"5.20.2-3+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-modules", ver:"5.20.2-3+deb8u4", rls:"DEB8"))) {
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
