# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=499253");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=478019");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=423234");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=420084");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=415678");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=511568");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=509914");
  script_oid("1.3.6.1.4.1.25623.1.0.65687");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-11 22:58:51 +0200 (Sun, 11 Oct 2009)");
  script_cve_id("CVE-2009-0642", "CVE-2008-3905", "CVE-2008-3790", "CVE-2008-3656", "CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3657", "CVE-2009-1904");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("SLES11: Security update for ruby");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0");
  script_tag(name:"solution", value:"Please install the updates provided by SuSE.");
  script_tag(name:"summary", value:"The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    ruby
    ruby-doc-html
    ruby-tk


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
if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.7.p72~5.22.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-doc-html", rpm:"ruby-doc-html~1.8.7.p72~5.22.1", rls:"SLES11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-tk", rpm:"ruby-tk~1.8.7.p72~5.22.1", rls:"SLES11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
