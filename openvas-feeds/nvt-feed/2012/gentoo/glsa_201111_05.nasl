# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70794");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-3892", "CVE-2011-3893", "CVE-2011-3894", "CVE-2011-3895", "CVE-2011-3896", "CVE-2011-3897", "CVE-2011-3898", "CVE-2011-3900");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:41 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201111-05 (chromium v8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been reported in Chromium and V8,
    some of which may allow execution of arbitrary code.");
  script_tag(name:"solution", value:"All Chromium users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/chromium-15.0.874.121'


All V8 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/v8-3.5.10.24'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201111-05");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=390113");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=390779");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/11/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/11/stable-channel-update_16.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201111-05.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"www-client/chromium", unaffected: make_list("ge 15.0.874.121"), vulnerable: make_list("lt 15.0.874.121"))) != NULL ) {
    report += res;
}
if((res = ispkgvuln(pkg:"dev-lang/v8", unaffected: make_list("ge 3.5.10.24"), vulnerable: make_list("lt 3.5.10.24"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
