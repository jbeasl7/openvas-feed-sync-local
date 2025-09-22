# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=547555");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=550072");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=549487");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=540247");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=550917");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=547624");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=550732");
  script_oid("1.3.6.1.4.1.25623.1.0.66313");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-11-23 20:51:51 +0100 (Mon, 23 Nov 2009)");
  script_cve_id("CVE-2009-3616", "CVE-2009-3638", "CVE-2009-3640");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 21:06:20 +0000 (Thu, 15 Feb 2024)");
  script_name("SLES11: Security update for KVM");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0");
  script_tag(name:"solution", value:"Please install the updates provided by SuSE.");
  script_tag(name:"summary", value:"The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    kvm
    kvm-kmp-default
    kvm-kmp-pae


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
if ((res = isrpmvuln(pkg:"kvm", rpm:"kvm~78.0.10.6~0.3.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kvm-kmp-default", rpm:"kvm-kmp-default~78.2.6.30.1_2.6.27.37_0.1~0.7.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kvm-kmp-pae", rpm:"kvm-kmp-pae~78.2.6.30.1_2.6.27.37_0.1~0.7.1", rls:"SLES11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
