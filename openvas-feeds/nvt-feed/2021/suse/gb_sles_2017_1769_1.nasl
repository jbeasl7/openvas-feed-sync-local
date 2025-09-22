# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1769.1");
  script_cve_id("CVE-2017-9122", "CVE-2017-9123", "CVE-2017-9124", "CVE-2017-9125", "CVE-2017-9126", "CVE-2017-9127", "CVE-2017-9128");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-15 15:48:49 +0000 (Thu, 15 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1769-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1769-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171769-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044122");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-July/003002.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libquicktime' package(s) announced via the SUSE-SU-2017:1769-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libquicktime fixes the following issues:

* CVE-2017-9122: A DoS in quicktime_read_moov function in moov.c via acrafted mp4 file was fixed. (bsc#1044077)
* CVE-2017-9123: An invalid memory read in lqt_frame_duration via a crafted mp4 file was fixed. (bsc#1044009)
* CVE-2017-9124: A NULL pointer dereference in quicktime_match_32 via a crafted mp4 file was fixed. (bsc#1044008)
* CVE-2017-9125: A DoS in lqt_frame_duration function in lqt_quicktime.c via crafted mp4 file was fixed. (bsc#1044122)
* CVE-2017-9126: A heap-based buffer overflow in quicktime_read_dref_table via a crafted mp4 file was fixed. (bsc#1044006)
* CVE-2017-9127: A heap-based buffer overflow in quicktime_user_atoms_read_atom via a crafted mp4 file was fixed. (bsc#1044002)
* CVE-2017-9128: A heap-based buffer over-read in quicktime_video_width via a crafted mp4 file was fixed. (bsc#1044000)");

  script_tag(name:"affected", value:"'libquicktime' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libquicktime0", rpm:"libquicktime0~1.2.4~13.1", rls:"SLES12.0SP2"))) {
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
