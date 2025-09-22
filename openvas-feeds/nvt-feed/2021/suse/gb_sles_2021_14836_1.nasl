# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14836.1");
  script_cve_id("CVE-2020-21529", "CVE-2020-21530", "CVE-2020-21531", "CVE-2020-21532", "CVE-2020-21533", "CVE-2020-21534", "CVE-2020-21535", "CVE-2021-32280");
  script_tag(name:"creation_date", value:"2021-11-02 14:44:50 +0000 (Tue, 02 Nov 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-02 03:10:20 +0000 (Sat, 02 Oct 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14836-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14836-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114836-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192019");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-November/009686.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'transfig' package(s) announced via the SUSE-SU-2021:14836-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for transfig fixes the following issues:

Update to fig2dev version 3.2.8 Patchlevel 8b (Aug 2021)

- bsc#1190618, CVE-2020-21529: stack buffer overflow in the bezier_spline function in genepic.c.
- bsc#1190615, CVE-2020-21530: segmentation fault in the read_objects function in read.c.
- bsc#1190617, CVE-2020-21531: global buffer overflow in the conv_pattern_index function in gencgm.c.
- bsc#1190616, CVE-2020-21532: global buffer overflow in the setfigfont function in genepic.c.
- bsc#1190612, CVE-2020-21533: stack buffer overflow in the read_textobject function in read.c.
- bsc#1190611, CVE-2020-21534: global buffer overflow in the get_line function in read.c.
- bsc#1190607, CVE-2020-21535: segmentation fault in the gencgm_start function in gencgm.c.
- bsc#1192019, CVE-2021-32280: NULL pointer dereference in compute_closed_spline() in trans_spline.c");

  script_tag(name:"affected", value:"'transfig' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"transfig", rpm:"transfig~3.2.8b~160.16.2", rls:"SLES11.0SP4"))) {
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
