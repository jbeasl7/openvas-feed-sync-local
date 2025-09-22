# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65822");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-13 18:25:40 +0200 (Tue, 13 Oct 2009)");
  script_cve_id("CVE-2008-5360", "CVE-2008-5359", "CVE-2008-5358", "CVE-2008-5357", "CVE-2008-5356", "CVE-2008-5344", "CVE-2008-5343", "CVE-2008-5342", "CVE-2008-5341", "CVE-2008-5340", "CVE-2008-5339", "CVE-2008-2086", "CVE-2008-5355", "CVE-2008-5354", "CVE-2008-5353", "CVE-2008-5352", "CVE-2008-5351", "CVE-2008-5350", "CVE-2008-5349", "CVE-2008-5348", "CVE-2008-5347", "CVE-2008-5345", "CVE-2008-5346");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SLES10: Security update for Sun Java 1.4.2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=SLES10\.0");
  script_tag(name:"solution", value:"Please install the updates provided by SuSE.");
  script_tag(name:"summary", value:"The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    java-1_4_2-sun
    java-1_4_2-sun-alsa
    java-1_4_2-sun-devel
    java-1_4_2-sun-jdbc
    java-1_4_2-sun-plugin


More details may also be found by searching for the SuSE
Enterprise Server 10 patch database linked in the references.");

  script_xref(name:"URL", value:"http://download.novell.com/patch/finder/");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"java-1_4_2-sun", rpm:"java-1_4_2-sun~1.4.2.19~0.3", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_4_2-sun-alsa", rpm:"java-1_4_2-sun-alsa~1.4.2.19~0.3", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_4_2-sun-devel", rpm:"java-1_4_2-sun-devel~1.4.2.19~0.3", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_4_2-sun-jdbc", rpm:"java-1_4_2-sun-jdbc~1.4.2.19~0.3", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1_4_2-sun-plugin", rpm:"java-1_4_2-sun-plugin~1.4.2.19~0.3", rls:"SLES10.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
