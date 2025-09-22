# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71569");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2011-1784");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:54 -0400 (Fri, 10 Aug 2012)");
  script_name("Gentoo Security Advisory GLSA 201207-07 (keepalived)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Keepalived uses world-writable PID files, allowing a local attacker
to kill arbitrary processes.");
  script_tag(name:"solution", value:"All Keepalived users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose
'>=sys-cluster/keepalived-1.2.2-r3'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201207-07");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=371469");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201207-07.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"sys-cluster/keepalived", unaffected: make_list("ge 1.2.2-r3"), vulnerable: make_list("lt 1.2.2-r3"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
