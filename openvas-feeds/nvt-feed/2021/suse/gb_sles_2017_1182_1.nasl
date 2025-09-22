# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1182.1");
  script_cve_id("CVE-2017-6827", "CVE-2017-6828", "CVE-2017-6829", "CVE-2017-6830", "CVE-2017-6831", "CVE-2017-6832", "CVE-2017-6833", "CVE-2017-6834", "CVE-2017-6835", "CVE-2017-6836", "CVE-2017-6837", "CVE-2017-6838", "CVE-2017-6839");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-17 13:19:06 +0000 (Fri, 17 Mar 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1182-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1182-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171182-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026988");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-May/002846.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'audiofile' package(s) announced via the SUSE-SU-2017:1182-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for audiofile fixes the following issues:

Security issues fixed:
- CVE-2017-6827: heap-based buffer overflow in MSADPCM::initializeCoefficients (MSADPCM.cpp) (bsc#1026979)
- CVE-2017-6828: heap-based buffer overflow in readValue (FileHandle.cpp) (bsc#1026980)
- CVE-2017-6829: global buffer overflow in decodeSample (IMA.cpp) (bsc#1026981)
- CVE-2017-6830: heap-based buffer overflow in alaw2linear_buf (G711.cpp) (bsc#1026982)
- CVE-2017-6831: heap-based buffer overflow in IMA::decodeBlockWAVE (IMA.cpp) (bsc#1026983)
- CVE-2017-6832: heap-based buffer overflow in MSADPCM::decodeBlock (MSADPCM.cpp) (bsc#1026984)
- CVE-2017-6833: divide-by-zero in BlockCodec::runPull (BlockCodec.cpp) (bsc#1026985)
- CVE-2017-6834: heap-based buffer overflow in ulaw2linear_buf (G711.cpp) (bsc#1026986)
- CVE-2017-6835: divide-by-zero in BlockCodec::reset1 (BlockCodec.cpp) (bsc#1026988)
- CVE-2017-6836: heap-based buffer overflow in Expand3To4Module::run (SimpleModule.h) (bsc#1026987)
- CVE-2017-6837, CVE-2017-6838, CVE-2017-6839: multiple ubsan crashes (bsc#1026978)");

  script_tag(name:"affected", value:"'audiofile' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"audiofile", rpm:"audiofile~0.2.6~142.17.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audiofile-32bit", rpm:"audiofile-32bit~0.2.6~142.17.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audiofile-x86", rpm:"audiofile-x86~0.2.6~142.17.1", rls:"SLES11.0SP4"))) {
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
