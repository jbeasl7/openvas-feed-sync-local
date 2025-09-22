# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703628");
  script_cve_id("CVE-2016-1238", "CVE-2016-6185");
  script_tag(name:"creation_date", value:"2016-08-02 05:26:30 +0000 (Tue, 02 Aug 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-03 17:18:29 +0000 (Wed, 03 Aug 2016)");

  script_name("Debian: Security Advisory (DSA-3628-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3628-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3628-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3628");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'perl' package(s) announced via the DSA-3628-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the implementation of the Perl programming language. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-1238

John Lightsey and Todd Rinaldo reported that the opportunistic loading of optional modules can make many programs unintentionally load code from the current working directory (which might be changed to another directory without the user realising) and potentially leading to privilege escalation, as demonstrated in Debian with certain combinations of installed packages.

The problem relates to Perl loading modules from the includes directory array ('@INC') in which the last element is the current directory ('.'). That means that, when perl wants to load a module (during first compilation or during lazy loading of a module in run time), perl will look for the module in the current directory at the end, since '.' is the last include directory in its array of include directories to seek. The issue is with requiring libraries that are in '.' but are not otherwise installed.

With this update several modules which are known to be vulnerable are updated to not load modules from current directory.

Additionally the update allows configurable removal of '.' from @INC in /etc/perl/sitecustomize.pl for a transitional period. It is recommended to enable this setting if the possible breakage for a specific site has been evaluated. Problems in packages provided in Debian resulting from the switch to the removal of '.' from @INC should be reported to the Perl maintainers at perl@packages.debian.org .

It is planned to switch to the default removal of '.' in @INC in a subsequent update to perl via a point release if possible, and in any case for the upcoming stable release Debian 9 (stretch).

CVE-2016-6185

It was discovered that XSLoader, a core module from Perl to dynamically load C libraries into Perl code, could load shared library from incorrect location. XSLoader uses caller() information to locate the .so file to load. This can be incorrect if XSLoader::load() is called in a string eval. An attacker can take advantage of this flaw to execute arbitrary code.

For the stable distribution (jessie), these problems have been fixed in version 5.20.2-3+deb8u6. Additionally this update includes the following updated packages to address optional module loading vulnerabilities related to CVE-2016-1238, or to address build failures which occur when '.' is removed from @INC:

cdbs 0.4.130+deb8u1

debhelper 9.20150101+deb8u2

devscripts 2.15.3+deb8u12

exim4 4.84.2-2+deb8u12

libintl-perl 1.23-1+deb8u12

libmime-charset-perl 1.011.1-1+deb8u22

libmime-encwords-perl 1.014.3-1+deb8u12

libmodule-build-perl 0.421000-2+deb8u12

libnet-dns-perl 0.81-2+deb8u12

libsys-syslog-perl 0.33-1+deb8u12

libunicode-linebreak-perl 0.0.20140601-2+deb8u22

We recommend that you upgrade your perl packages.");

  script_tag(name:"affected", value:"'perl' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libperl-dev", ver:"5.20.2-3+deb8u6", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libperl5.20", ver:"5.20.2-3+deb8u6", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl", ver:"5.20.2-3+deb8u6", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-base", ver:"5.20.2-3+deb8u6", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-debug", ver:"5.20.2-3+deb8u6", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-doc", ver:"5.20.2-3+deb8u6", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perl-modules", ver:"5.20.2-3+deb8u6", rls:"DEB8"))) {
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
