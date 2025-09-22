# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0929.1");
  script_cve_id("CVE-2011-1750", "CVE-2011-1751", "CVE-2011-2212", "CVE-2011-2512", "CVE-2011-2527", "CVE-2012-0029", "CVE-2012-2652", "CVE-2012-3515", "CVE-2014-0222", "CVE-2014-0223", "CVE-2015-3209", "CVE-2015-3456");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0929-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0929-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150929-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/598271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/598298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/599095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/603161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/603179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/610682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/619991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/621793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/626654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/637297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/689895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/690781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/695510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/695766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/698237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/701161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/702823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/704933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/705095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/705304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/740165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/764526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/777084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/877642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/877645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932770");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-May/001402.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2015:0929-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kvm qemu vt100 emulation was affected by a problem where specific vt100
sequences could have been used by guest users to affect the host.
(CVE-2012-3515 aka XSA-17).

Also a temp file race was fixed. (CVE-2012-2652)

Security Issue reference:

 * CVE-2012-3515
 <[link moved to references]>
 * CVE-2012-2652
 <[link moved to references]>");

  script_tag(name:"affected", value:"'kvm' package(s) on SUSE Linux Enterprise Server 11-SP1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~0.12.5~1.24.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
