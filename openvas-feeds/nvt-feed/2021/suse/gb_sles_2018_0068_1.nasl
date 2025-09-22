# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0068.1");
  script_cve_id("CVE-2017-5715");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:49 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 14:52:07 +0000 (Wed, 14 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0068-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0068-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180068-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075262");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-January/003587.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl' package(s) announced via the SUSE-SU-2018:0068-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to Intel microcode version 20180108 (bsc#1075262 CVE-2017-5715)

- The pre-released microcode fixing some important security issues
 is now officially published (and included in the added tarball).

Among other updates it contains:

- IVT C0 (06-3e-04:ed) 428->42a
- SKL-U/Y D0 (06-4e-03:c0) ba->c2
- BDW-U/Y E/F (06-3d-04:c0) 25->28
- HSW-ULT Cx/Dx (06-45-01:72) 20->21
- Crystalwell Cx (06-46-01:32) 17->18
- BDW-H E/G (06-47-01:22) 17->1b
- HSX-EX E0 (06-3f-04:80) 0f->10
- SKL-H/S R0 (06-5e-03:36) ba->c2
- HSW Cx/Dx (06-3c-03:32) 22->23
- HSX C0 (06-3f-02:6f) 3a->3b
- BDX-DE V0/V1 (06-56-02:10) 0f->14
- BDX-DE V2 (06-56-03:10) 700000d->7000011
- KBL-U/Y H0 (06-8e-09:c0) 62->80
- KBL Y0 / CFL D0 (06-8e-0a:c0) 70->80
- KBL-H/S B0 (06-9e-09:2a) 5e->80
- CFL U0 (06-9e-0a:22) 70->80
- CFL B0 (06-9e-0b:02) 72->80
- SKX H0 (06-55-04:b7) 2000035->200003c
- GLK B0 (06-7a-01:01) 1e->22");

  script_tag(name:"affected", value:"'microcode_ctl' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~1.17~102.83.9.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~1.17~102.83.9.1", rls:"SLES11.0SP4"))) {
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
