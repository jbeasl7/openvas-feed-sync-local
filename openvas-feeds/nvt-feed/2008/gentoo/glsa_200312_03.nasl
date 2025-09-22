# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54509");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2003-0962");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200312-03 (rsync)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"rsync contains a heap overflow vulnerability that can be used to execute
arbitrary code.");
  script_tag(name:"solution", value:"To address this vulnerability, all Gentoo users should read GLSA-200312-02
and ensure that all systems are upgraded to a version of the Linux kernel
without the do_brk() vulnerability, and upgrade to version 2.5.7 of rsync:

    # emerge sync
    # emerge -pv '>=net-misc/rsync-2.5.7'
    # emerge '>=net-misc/rsync-2.5.7'
    # emerge clean

Review your /etc/rsync/rsyncd.conf configuration file. Ensure that the use
chroot='no' command is commented out or removed, or change use chroot='no'
to use chroot='yes'.  Then, if necessary, restart rsyncd:

    # /etc/init.d/rsyncd restart");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200312-03");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9153");
  script_xref(name:"URL", value:"http://rsync.samba.org/#security_dec03");
  script_xref(name:"URL", value:"http://security.gentoo.org/glsa/glsa-200312-02.xml");
  script_xref(name:"URL", value:"http://security.gentoo.org/glsa/glsa-200312-01.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200312-03.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-misc/rsync", unaffected: make_list("ge 2.5.7"), vulnerable: make_list("lt 2.5.6*"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
