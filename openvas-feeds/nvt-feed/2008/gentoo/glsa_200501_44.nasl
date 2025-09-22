# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54830");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-0013", "CVE-2005-0014");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200501-44 (ncpfs)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"The ncpfs utilities contain multiple flaws, potentially resulting in the
remote execution of arbitrary code or local file access with elevated
privileges.");
  script_tag(name:"solution", value:"All ncpfs users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-fs/ncpfs-2.2.6'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200501-44");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=77414");
  script_xref(name:"URL", value:"ftp://platan.vc.cvut.cz/pub/linux/ncpfs/Changes-2.2.6");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200501-44.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-fs/ncpfs", unaffected: make_list("ge 2.2.6"), vulnerable: make_list("lt 2.2.6"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
