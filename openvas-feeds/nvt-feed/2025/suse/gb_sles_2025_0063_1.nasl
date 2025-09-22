# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0063.1");
  script_cve_id("CVE-2024-47537", "CVE-2024-47540", "CVE-2024-47543", "CVE-2024-47544", "CVE-2024-47545", "CVE-2024-47596", "CVE-2024-47597", "CVE-2024-47599", "CVE-2024-47601", "CVE-2024-47602", "CVE-2024-47603", "CVE-2024-47606", "CVE-2024-47613", "CVE-2024-47774", "CVE-2024-47775", "CVE-2024-47776", "CVE-2024-47777", "CVE-2024-47778", "CVE-2024-47834");
  script_tag(name:"creation_date", value:"2025-01-13 04:17:21 +0000 (Mon, 13 Jan 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-18 19:55:43 +0000 (Wed, 18 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0063-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0063-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250063-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234476");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020091.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-plugins-good' package(s) announced via the SUSE-SU-2025:0063-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-plugins-good fixes the following issues:

- CVE-2024-47540: Fixed an uninitialized stack memory in Matroska/WebM demuxer. (boo#1234421)
- CVE-2024-47537: Fixed an out-of-bounds write in isomp4/qtdemux.c. (boo#1234414)
- CVE-2024-47543: Fixed an out-of-bounds write in qtdemux_parse_container. (boo#1234462)
- CVE-2024-47544: Fixed a NULL-pointer dereferences in MP4/MOV demuxer CENC handling. (boo#1234473)
- CVE-2024-47545: Fixed an integer underflow in FOURCC_strf parsing leading to out-of-bounds read. (boo#1234476)
- CVE-2024-47596: Fixed an integer underflow in MP4/MOV demuxer that can lead to out-of-bounds reads. (boo#1234424)
- CVE-2024-47597: Fixed an out-of-bounds reads in MP4/MOV demuxer sample table parser (boo#1234425)
- CVE-2024-47599: Fixed insufficient error handling in JPEG decoder that can lead to NULL-pointer dereferences. (boo#1234427)
- CVE-2024-47601: Fixed a NULL-pointer dereference in Matroska/WebM demuxer. (boo#1234428)
- CVE-2024-47602: Fixed a NULL-pointer dereferences and out-of-bounds reads in Matroska/WebM demuxer. (boo#1234432)
- CVE-2024-47603: Fixed a NULL-pointer dereference in Matroska/WebM demuxer. (boo#1234433)
- CVE-2024-47606: Avoid integer overflow when allocating sysmem. (bsc#1234449)
- CVE-2024-47606: Fixed an integer overflows in MP4/MOV demuxer and memory allocator that can lead to out-of-bounds writes. (boo#1234449)
- CVE-2024-47613: Fixed a NULL-pointer dereference in gdk-pixbuf decoder. (boo#1234447)
- CVE-2024-47774: Fixed an integer overflow in AVI subtitle parser that leads to out-of-bounds reads. (boo#1234446)
- CVE-2024-47775: Fixed various out-of-bounds reads in WAV parser. (boo#1234434)
- CVE-2024-47776: Fixed various out-of-bounds reads in WAV parser. (boo#1234435)
- CVE-2024-47777: Fixed various out-of-bounds reads in WAV parser. (boo#1234436)
- CVE-2024-47778: Fixed various out-of-bounds reads in WAV parser. (boo#1234439)
- CVE-2024-47834: Fixed a use-after-free in the Matroska demuxer that can cause crashes for certain input files. (boo#1234440)");

  script_tag(name:"affected", value:"'gstreamer-plugins-good' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good", rpm:"gstreamer-plugins-good~1.8.3~16.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-lang", rpm:"gstreamer-plugins-good-lang~1.8.3~16.12.1", rls:"SLES12.0SP5"))) {
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
