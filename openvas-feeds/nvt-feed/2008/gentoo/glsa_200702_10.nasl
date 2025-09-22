# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58057");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2006-3788", "CVE-2006-3789", "CVE-2006-3790", "CVE-2006-3791", "CVE-2006-3792");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200702-10 (ufo2000)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in the network components of
UFO2000 that could result in the remote execution of arbitrary code.");
  script_tag(name:"solution", value:"UFO2000 currently depends on the dumb-0.9.2 library, which has been removed
from portage due to security problems (GLSA 200608-14). Because of this,
UFO2000 has been masked, and we recommend unmerging the package until the
next beta release can remove the dependency on dumb.

    # emerge --ask --verbose --unmerge ufo2000");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200702-10");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=142392");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200608-14.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200702-10.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"games-strategy/ufo2000", unaffected: make_list("ge 0.7.1062"), vulnerable: make_list("lt 0.7.1062"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
