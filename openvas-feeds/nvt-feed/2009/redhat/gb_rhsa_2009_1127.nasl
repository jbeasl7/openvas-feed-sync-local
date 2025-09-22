# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64280");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
  script_cve_id("CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1698");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:1127");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1127.

The kdelibs packages provide libraries for the K Desktop Environment (KDE).

A flaw was found in the way the KDE CSS parser handled content for the
CSS style attribute. A remote attacker could create a specially-crafted
CSS equipped HTML page, which once visited by an unsuspecting user, could
cause a denial of service (Konqueror crash) or, potentially, execute
arbitrary code with the privileges of the user running Konqueror.
(CVE-2009-1698)

A flaw was found in the way the KDE HTML parser handled content for the
HTML head element. A remote attacker could create a specially-crafted
HTML page, which once visited by an unsuspecting user, could cause a denial
of service (Konqueror crash) or, potentially, execute arbitrary code with
the privileges of the user running Konqueror. (CVE-2009-1690)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way the KDE JavaScript garbage collector handled memory
allocation requests. A remote attacker could create a specially-crafted
HTML page, which once visited by an unsuspecting user, could cause a denial
of service (Konqueror crash) or, potentially, execute arbitrary code with
the privileges of the user running Konqueror. (CVE-2009-1687)

Users should upgrade to these updated packages, which contain backported
patches to correct these issues. The desktop must be restarted (log out,
then log back in) for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1127.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#critical");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kdelibs", rpm:"kdelibs~3.3.1~14.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-debuginfo", rpm:"kdelibs-debuginfo~3.3.1~14.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-devel", rpm:"kdelibs-devel~3.3.1~14.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs", rpm:"kdelibs~3.5.4~22.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-apidocs", rpm:"kdelibs-apidocs~3.5.4~22.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-debuginfo", rpm:"kdelibs-debuginfo~3.5.4~22.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs-devel", rpm:"kdelibs-devel~3.5.4~22.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
