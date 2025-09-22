# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.59243");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0813", "CVE-2006-3619", "CVE-2006-4146", "CVE-2006-4600", "CVE-2007-0061", "CVE-2007-0062", "CVE-2007-0063", "CVE-2007-1716", "CVE-2007-4496", "CVE-2007-4497", "CVE-2007-5617");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200711-23 (vmware-workstation vmware-player)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"VMware guest operating systems might be able to execute arbitrary code with
elevated privileges on the host operating system through multiple flaws.");
  script_tag(name:"solution", value:"All VMware Workstation users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=app-emulation/vmware-workstation-5.5.5.56455'

All VMware Player users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=app-emulation/vmware-player-1.0.5.56455'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200711-23");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=193196");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200606-02.xml");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200702-06.xml");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200704-11.xml");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200705-15.xml");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200707-11.xml");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2007/000001.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200711-23.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-emulation/vmware-workstation", unaffected: make_list("rge 5.5.5.56455", "ge 6.0.1.55017"), vulnerable: make_list("lt 6.0.1.55017"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-emulation/vmware-player", unaffected: make_list("rge 1.0.5.56455", "ge 2.0.1.55017"), vulnerable: make_list("lt 2.0.1.55017"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
