# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70791");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3550", "CVE-2010-3551", "CVE-2010-3552", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3555", "CVE-2010-3556", "CVE-2010-3557", "CVE-2010-3558", "CVE-2010-3559", "CVE-2010-3560", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3563", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3570", "CVE-2010-3571", "CVE-2010-3572", "CVE-2010-3573", "CVE-2010-3574", "CVE-2010-4422", "CVE-2010-4447", "CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4451", "CVE-2010-4452", "CVE-2010-4454", "CVE-2010-4462", "CVE-2010-4463", "CVE-2010-4465", "CVE-2010-4466", "CVE-2010-4467", "CVE-2010-4468", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4471", "CVE-2010-4472", "CVE-2010-4473", "CVE-2010-4474", "CVE-2010-4475", "CVE-2010-4476", "CVE-2011-0802", "CVE-2011-0814", "CVE-2011-0815", "CVE-2011-0862", "CVE-2011-0863", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0871", "CVE-2011-0872", "CVE-2011-0873", "CVE-2011-3389", "CVE-2011-3516", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3545", "CVE-2011-3546", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3549", "CVE-2011-3550", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553", "CVE-2011-3554", "CVE-2011-3555", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3558", "CVE-2011-3560", "CVE-2011-3561");
  script_version("2024-07-25T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-07-25 05:05:41 +0000 (Thu, 25 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 14:29:45 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:40 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201111-02 (sun-jre-bin sun-jdk emul-linux-x86-java)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in the Oracle JRE/JDK,
    allowing attackers to cause unspecified impact.");
  script_tag(name:"solution", value:"All Oracle JDK 1.6 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.6.0.29'


All Oracle JRE 1.6 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.6.0.29'


All users of the precompiled 32-bit Oracle JRE 1.6 should upgrade to the
      latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/emul-linux-x86-java-1.6.0.29'


NOTE: As Oracle has revoked the DLJ license for its Java implementation,
      the packages can no longer be updated automatically. This limitation
is
      not present on a non-fetch restricted implementation such as
      dev-java/icedtea-bin.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201111-02");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=340421");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=354213");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=370559");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=387851");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201111-02.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"dev-java/sun-jre-bin", unaffected: make_list("ge 1.6.0.29"), vulnerable: make_list("lt 1.6.0.29"))) != NULL ) {
    report += res;
}
if((res = ispkgvuln(pkg:"app-emulation/emul-linux-x86-java", unaffected: make_list("ge 1.6.0.29"), vulnerable: make_list("lt 1.6.0.29"))) != NULL ) {
    report += res;
}
if((res = ispkgvuln(pkg:"dev-java/sun-jdk", unaffected: make_list("ge 1.6.0.29"), vulnerable: make_list("lt 1.6.0.29"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
