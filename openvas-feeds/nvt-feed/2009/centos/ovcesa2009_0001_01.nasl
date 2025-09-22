# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63344");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2009-02-10 15:52:40 +0100 (Tue, 10 Feb 2009)");
  script_cve_id("CVE-2006-4814", "CVE-2007-2172", "CVE-2007-3848", "CVE-2007-4308", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2008-0007", "CVE-2008-2136", "CVE-2008-3275", "CVE-2008-3525", "CVE-2008-4210");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 15:36:00 +0000 (Fri, 14 Aug 2020)");
  script_name("CentOS Security Advisory CESA-2009:0001-01 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS2");
  script_tag(name:"insight", value:"For details on the issues addressed in this update,
please visit the referenced security advisories.");
  script_tag(name:"solution", value:"Update the appropriate packages on your system.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=CESA-2009:0001-01");
  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=RHSA-2009:0001");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/rh21as-errata.html");
  script_tag(name:"summary", value:"The remote host is missing updates to kernel announced in
advisory CESA-2009:0001-01.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.4.9~e.74", rls:"CentOS2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-BOOT", rpm:"kernel-BOOT~2.4.9~e.74", rls:"CentOS2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.4.9~e.74", rls:"CentOS2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.4.9~e.74", rls:"CentOS2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-enterprise", rpm:"kernel-enterprise~2.4.9~e.74", rls:"CentOS2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.4.9~e.74", rls:"CentOS2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.4.9~e.74", rls:"CentOS2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.4.9~e.74", rls:"CentOS2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-summit", rpm:"kernel-summit~2.4.9~e.74", rls:"CentOS2")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
