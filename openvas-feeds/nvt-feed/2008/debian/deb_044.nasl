# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53805");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 044-1 (mailx)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20044-1");
  script_tag(name:"insight", value:"The mail program (a simple tool to read and send email) as
distributed with Debian GNU/Linux 2.2 has a buffer overflow in the
input parsing code. Since mail is installed setgid mail by default
this allowed local users to use it to gain access to mail group.

Since the mail code was never written to be secure fixing it
properly would mean a large rewrite. Instead of doing this we
decided to no longer install it setgid. This means that it can no
longer lock your mailbox properly on systems for which you need
group mail to write to the mailspool, but it will still work for
sending email.

This has been fixed in mailx version 8.1.1-10.1.5. If you have
suidmanager installed you can also make this manually with the
following command:

suidregister /usr/bin/mail root root 0755");
  script_tag(name:"summary", value:"The remote host is missing an update to mailx
announced via advisory DSA 044-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"mailx", ver:"8.1.1-10.1.5", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
