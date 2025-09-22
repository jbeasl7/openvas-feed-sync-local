# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63135");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-01-13 22:38:32 +0100 (Tue, 13 Jan 2009)");
  script_cve_id("CVE-2008-5081");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Security Advisory RHSA-2009:0013");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0013.

Hugo Dias discovered a denial of service flaw in avahi-daemon. A remote
attacker on the same local area network (LAN) could send a
specially-crafted mDNS (Multicast DNS) packet that would cause avahi-daemon
to exit unexpectedly due to a failed assertion check. (CVE-2008-5081)

All users are advised to upgrade to these updated packages, which contain a
backported patch which resolves this issue. After installing the update,
avahi-daemon will be restarted automatically.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0013.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.6.16~1.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-compat-howl", rpm:"avahi-compat-howl~0.6.16~1.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-compat-libdns_sd", rpm:"avahi-compat-libdns_sd~0.6.16~1.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-debuginfo", rpm:"avahi-debuginfo~0.6.16~1.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-glib", rpm:"avahi-glib~0.6.16~1.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-qt3", rpm:"avahi-qt3~0.6.16~1.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-tools", rpm:"avahi-tools~0.6.16~1.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-compat-howl-devel", rpm:"avahi-compat-howl-devel~0.6.16~1.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-compat-libdns_sd-devel", rpm:"avahi-compat-libdns_sd-devel~0.6.16~1.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-devel", rpm:"avahi-devel~0.6.16~1.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-glib-devel", rpm:"avahi-glib-devel~0.6.16~1.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"avahi-qt3-devel", rpm:"avahi-qt3-devel~0.6.16~1.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
