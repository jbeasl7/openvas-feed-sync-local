# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=490696");
  script_oid("1.3.6.1.4.1.25623.1.0.65655");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-11 22:58:51 +0200 (Sun, 11 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("SLES11: Security update for KDE4 PIM packages");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0");
  script_tag(name:"solution", value:"Please install the updates provided by SuSE.");
  script_tag(name:"summary", value:"The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    kde4-akonadi
    kde4-akregator
    kde4-kaddressbook
    kde4-kalarm
    kde4-kjots
    kde4-kmail
    kde4-knode
    kde4-knotes
    kde4-kontact
    kde4-korganizer
    kde4-ktimetracker
    kde4-ktnef
    kdepim4
    kdepim4-wizards
    kdepimlibs4
    libakonadi4
    libkdepim4
    libkdepimlibs4

More details may also be found by searching for the SuSE
Enterprise Server 11 patch database linked in the references.");

  script_xref(name:"URL", value:"http://download.novell.com/patch/finder/");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kde4-akonadi", rpm:"kde4-akonadi~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-akregator", rpm:"kde4-akregator~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-kaddressbook", rpm:"kde4-kaddressbook~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-kalarm", rpm:"kde4-kalarm~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-kjots", rpm:"kde4-kjots~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-kmail", rpm:"kde4-kmail~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-knode", rpm:"kde4-knode~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-knotes", rpm:"kde4-knotes~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-kontact", rpm:"kde4-kontact~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-korganizer", rpm:"kde4-korganizer~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-ktimetracker", rpm:"kde4-ktimetracker~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kde4-ktnef", rpm:"kde4-ktnef~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdepim4", rpm:"kdepim4~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdepim4-wizards", rpm:"kdepim4-wizards~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdepimlibs4", rpm:"kdepimlibs4~4.1.3~9.28.3", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libakonadi4", rpm:"libakonadi4~4.1.3~9.28.3", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdepim4", rpm:"libkdepim4~4.1.3~9.14.6", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdepimlibs4", rpm:"libkdepimlibs4~4.1.3~9.28.3", rls:"SLES11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
