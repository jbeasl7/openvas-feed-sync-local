# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54511");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2003-0971");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Gentoo Security Advisory GLSA 200312-05 (GnuPG)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");

  script_tag(name:"insight", value:"A bug in GnuPG allows ElGamal signing keys to be compromised, and a format
  string bug in the gpgkeys_hkp utility may allow arbitrary code execution.");

  script_tag(name:"solution", value:"All users who have created ElGamal signing keys should immediately revoke
  them. In addition, all Gentoo Linux machines with gnupg installed should be updated to use gnupg-1.2.3-r5 or higher:

  # emerge sync

  # emerge -pv '>=app-crypt/gnupg-1.2.3-r5'

  # emerge '>=app-crypt/gnupg-1.2.3-r5'

  # emerge clean");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200312-05");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9115");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=34504");
  script_xref(name:"URL", value:"http://marc.info/?l=gnupg-announce&m=106992378510843&q=raw");
  script_xref(name:"URL", value:"http://www.s-quadra.com/advisories/Adv-20031203.txt");

  script_tag(name:"summary", value:"The remote host is missing updates announced in
  advisory GLSA 200312-05.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";

if ((res = ispkgvuln(pkg:"app-crypt/gnupg", unaffected: make_list("ge 1.2.3-r5"), vulnerable: make_list("le 1.2.3-r4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
