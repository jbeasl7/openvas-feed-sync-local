# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.113");
  script_cve_id("CVE-2014-7844");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-21 16:05:13 +0000 (Tue, 21 Jan 2020)");

  script_name("Debian: Security Advisory (DLA-113-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-113-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/DLA-113-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bsd-mailx' package(s) announced via the DLA-113-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that bsd-mailx, an implementation of the mail command, had an undocumented feature which treats syntactically valid email addresses as shell commands to execute.

Users who need this feature can re-enable it using the expandaddr in an appropriate mailrc file. This update also removes the obsolete -T option. An older security vulnerability, CVE-2004-2771, had already been addressed in the Debian's bsd-mailx package.

Note that this security update does not remove all mailx facilities for command execution, though. Scripts which send mail to addresses obtained from an untrusted source (such as a web form) should use the '--' separator before the email addresses (which was fixed to work properly in this update), or they should be changed to invoke 'mail -t' or 'sendmail -i -t' instead, passing the recipient addresses as part of the mail header.

For the oldstable distribution (squeeze), this problem has been fixed in version 8.1.2-0.20100314cvs-1+deb6u1.

We recommend that you upgrade your bsd-mailx packages.");

  script_tag(name:"affected", value:"'bsd-mailx' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bsd-mailx", ver:"8.1.2-0.20100314cvs-1+deb6u1", rls:"DEB6"))) {
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
