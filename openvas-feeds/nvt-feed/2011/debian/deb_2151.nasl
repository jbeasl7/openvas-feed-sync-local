# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68989");
  script_cve_id("CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-3689", "CVE-2010-4253", "CVE-2010-4643");
  script_tag(name:"creation_date", value:"2011-03-07 15:04:02 +0000 (Mon, 07 Mar 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2151-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2151-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2151-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2151");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openoffice.org' package(s) announced via the DSA-2151-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in the OpenOffice.org package that allows malformed documents to trick the system into crashes or even the execution of arbitrary code.

CVE-2010-3450

During an internal security audit within Red Hat, a directory traversal vulnerability has been discovered in the way OpenOffice.org 3.1.1 through 3.2.1 processes XML filter files. If a local user is tricked into opening a specially-crafted OOo XML filters package file, this problem could allow remote attackers to create or overwrite arbitrary files belonging to local user or, potentially, execute arbitrary code.

CVE-2010-3451

During his work as a consultant at Virtual Security Research (VSR), Dan Rosenberg discovered a vulnerability in OpenOffice.org's RTF parsing functionality. Opening a maliciously crafted RTF document can cause an out-of-bounds memory read into previously allocated heap memory, which may lead to the execution of arbitrary code.

CVE-2010-3452

Dan Rosenberg discovered a vulnerability in the RTF file parser which can be leveraged by attackers to achieve arbitrary code execution by convincing a victim to open a maliciously crafted RTF file.

CVE-2010-3453

As part of his work with Virtual Security Research, Dan Rosenberg discovered a vulnerability in the WW8ListManager::WW8ListManager() function of OpenOffice.org that allows a maliciously crafted file to cause the execution of arbitrary code.

CVE-2010-3454

As part of his work with Virtual Security Research, Dan Rosenberg discovered a vulnerability in the WW8DopTypography::ReadFromMem() function in OpenOffice.org that may be exploited by a maliciously crafted file which allows an attacker to control program flow and potentially execute arbitrary code.

CVE-2010-3689

Dmitri Gribenko discovered that the soffice script does not treat an empty LD_LIBRARY_PATH variable like an unset one, which may lead to the execution of arbitrary code.

CVE-2010-4253

A heap based buffer overflow has been discovered with unknown impact.

CVE-2010-4643

A vulnerability has been discovered in the way OpenOffice.org handles TGA graphics which can be tricked by a specially crafted TGA file that could cause the program to crash due to a heap-based buffer overflow with unknown impact.

For the stable distribution (lenny) these problems have been fixed in version 2.4.1+dfsg-1+lenny11.

For the upcoming stable distribution (squeeze) these problems have been fixed in version 3.2.1-11+squeeze1.

For the unstable distribution (sid) these problems have been fixed in version 3.2.1-11+squeeze1.

For the experimental distribution these problems have been fixed in version 3.3.0~rc3-1.

We recommend that you upgrade your OpenOffice.org packages.");

  script_tag(name:"affected", value:"'openoffice.org' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"broffice.org", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cli-uno-bridge", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmythes-dev", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-cli-basetypes1.0-cil", ver:"1.0.10.0+OOo2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-cli-cppuhelper1.0-cil", ver:"1.0.13.0+OOo2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-cli-types1.1-cil", ver:"1.1.13.0+OOo2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-cli-ure1.0-cil", ver:"1.0.13.0+OOo2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-openoffice.org", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-base", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-base-core", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-calc", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-common", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-core", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dbg", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dev-doc", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-draw", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dtd-officedocument1.0", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-emailmerge", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-filter-binfilter", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-filter-mobiledev", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gcj", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gnome", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gtk", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-headless", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-cs", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-da", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-de", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-dz", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-en-gb", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-en-us", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-es", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-et", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-eu", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-fr", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-gl", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-hi-in", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-hu", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-it", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-ja", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-km", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-ko", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-nl", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-pl", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-pt", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-pt-br", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-ru", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-sl", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-sv", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-zh-cn", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-zh-tw", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-impress", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-java-common", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-af", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ar", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-as-in", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-be-by", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-bg", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-bn", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-br", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-bs", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ca", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-cs", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-cy", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-da", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-de", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-dz", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-el", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-en-gb", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-en-za", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-eo", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-es", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-et", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-eu", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fa", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fi", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fr", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ga", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-gl", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-gu-in", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-he", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hi-in", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hr", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hu", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-in", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-it", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ja", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ka", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-km", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ko", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ku", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-lo", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-lt", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-lv", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-mk", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ml-in", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-mr-in", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nb", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ne", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nl", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nn", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nr", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ns", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-or-in", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pa-in", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pl", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pt", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pt-br", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ro", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ru", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-rw", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sk", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sl", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sr", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sr-cs", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ss", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-st", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sv", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ta-in", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-te-in", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tg", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-th", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tn", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tr", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ts", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-uk", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-uz", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ve", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-vi", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-xh", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-za", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-cn", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-tw", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zu", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-math", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-officebean", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-ogltrans", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-presentation-minimizer", ver:"1.0+OOo2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-qa-api-tests", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-qa-tools", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-report-builder", ver:"1:1.0.2+OOo2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-report-builder-bin", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-sdbc-postgresql", ver:"1:0.7.6+OOo2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-style-andromeda", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-style-crystal", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-style-hicontrast", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-style-industrial", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-style-tango", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-writer", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-uno", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"1:2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ure", ver:"1.4+OOo2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ure-dbg", ver:"1.4+OOo2.4.1+dfsg-1+lenny11", rls:"DEB5"))) {
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
