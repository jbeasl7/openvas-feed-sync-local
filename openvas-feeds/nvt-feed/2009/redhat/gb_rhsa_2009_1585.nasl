# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66243");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-11-17 21:42:12 +0100 (Tue, 17 Nov 2009)");
  script_cve_id("CVE-2009-1888", "CVE-2009-2813", "CVE-2009-2906", "CVE-2009-2948");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("RedHat Security Advisory RHSA-2009:1585");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1585.

Samba is a suite of programs used by machines to share files, printers, and
other information. These samba3x packages provide Samba 3.3, which is a
Technology Preview for Red Hat Enterprise Linux 5. These packages cannot be
installed in parallel with the samba packages. Note: Technology Previews
are not intended for production use.

A denial of service flaw was found in the Samba smbd daemon. An
authenticated, remote user could send a specially-crafted response that
would cause an smbd child process to enter an infinite loop. An
authenticated, remote user could use this flaw to exhaust system resources
by opening multiple CIFS sessions. (CVE-2009-2906)

An uninitialized data access flaw was discovered in the smbd daemon when
using the non-default dos filemode configuration option in smb.conf. An
authenticated, remote user with write access to a file could possibly use
this flaw to change an access control list for that file, even when such
access should have been denied. (CVE-2009-1888)

A flaw was discovered in the way Samba handled users without a home
directory set in the back-end password database (e.g. /etc/passwd). If a
share for the home directory of such a user was created (e.g. using the
automated [homes] share), any user able to access that share could see
the whole file system, possibly bypassing intended access restrictions.
(CVE-2009-2813)

The mount.cifs program printed CIFS passwords as part of its debug output
when running in verbose mode. When mount.cifs had the setuid bit set, a
local, unprivileged user could use this flaw to disclose passwords from a
file that would otherwise be inaccessible to that user. Note: mount.cifs
from the samba3x packages distributed by Red Hat does not have the setuid
bit set. This flaw only affected systems where the setuid bit was manually
set by an administrator. (CVE-2009-2948)

These packages upgrade Samba from version 3.3.5 to version 3.3.8. Refer to
the Samba Release Notes for a list of changes between versions:

Users of samba3x should upgrade to these updated packages, which resolve
these issues. After installing this update, the smb service will be
restarted automatically.");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");

  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1585.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");
  script_xref(name:"URL", value:"http://www.redhat.com/support/policy/soc/production/preview_scope/");
  script_xref(name:"URL", value:"http://samba.org/samba/history/");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~3.0.34~46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~3.0.34~46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtalloc", rpm:"libtalloc~1.2.0~46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtalloc-devel", rpm:"libtalloc-devel~1.2.0~46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtdb", rpm:"libtdb~1.1.2~46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtdb-devel", rpm:"libtdb-devel~1.1.2~46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba3x", rpm:"samba3x~3.3.8~0.46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba3x-client", rpm:"samba3x-client~3.3.8~0.46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba3x-common", rpm:"samba3x-common~3.3.8~0.46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba3x-debuginfo", rpm:"samba3x-debuginfo~3.3.8~0.46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba3x-doc", rpm:"samba3x-doc~3.3.8~0.46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba3x-domainjoin-gui", rpm:"samba3x-domainjoin-gui~3.3.8~0.46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba3x-swat", rpm:"samba3x-swat~3.3.8~0.46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba3x-winbind", rpm:"samba3x-winbind~3.3.8~0.46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba3x-winbind-devel", rpm:"samba3x-winbind-devel~3.3.8~0.46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tdb-tools", rpm:"tdb-tools~1.1.2~46.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
