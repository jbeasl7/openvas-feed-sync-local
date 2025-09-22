# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53850");
  script_cve_id("CVE-2002-0639", "CVE-2002-0640");
  script_version("2024-09-10T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-09-10 05:05:42 +0000 (Tue, 10 Sep 2024)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 18:37:46 +0000 (Thu, 08 Feb 2024)");
  script_name("Debian Security Advisory DSA 134-1 (ssh)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20134-1");
  script_tag(name:"insight", value:"Theo de Raadt announced that the OpenBSD team is working with ISS
on a remote exploit for OpenSSH (a free implementation of the
Secure SHell protocol). They are refusing to provide any details on
the vulnerability but instead are advising everyone to upgrade to
the latest release, version 3.3.

This version was released 3 days ago and introduced a new feature
to reduce the effect of exploits in the network handling code
called privilege separation.  Unfortunately this release has a few
known problems: compression does not work on all operating systems
since the code relies on specific mmap features, and the PAM
support has not been completed. There may be other problems as
well.

The new privilege separation support from Niels Provos changes ssh
to use a separate non-privileged process to handle most of the
work. This means any vulnerability in this part of OpenSSH can
never lead to a root compromise but only to access to a separate
account restricted to a chroot.

Theo made it very clear this new version does not fix the
vulnerability, instead by using the new privilege separation code
it merely reduces the risk since the attacker can only gain access
to a special account restricted in a chroot.

Since details of the problem have not been released we were forced
to move to the latest release of OpenSSH portable, version 3.3p1.

Due to the short time frame we have had we have not been able to
update the ssh package for Debian GNU/Linux 2.2 / potato yet.
Packages for the upcoming 3.0 release (woody) are available for
most architectures.

Please note that we have not had the time to do proper QA on these
packages. They might contain bugs or break things unexpectedly. If
you notice any such problems please file a bug-report so we can
investigate.

This package introduce a new account called `sshd' that is used in
the privilege separation code. If no sshd account exists the
package will try to create one. If the account already exists it
will be re-used. If you do not want this to happen you will have
to fix this manually.");
  script_tag(name:"summary", value:"The remote host is missing an update to ssh
announced via advisory DSA 134-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ssh", ver:"3.3p1-0.0woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"3.3p1-0.0woody1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
