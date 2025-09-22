# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1962.1");
  script_cve_id("CVE-2017-9111", "CVE-2017-9112", "CVE-2017-9113", "CVE-2017-9115", "CVE-2018-18444");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-30 19:42:31 +0000 (Fri, 30 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1962-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1962-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191962-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113455");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-July/005747.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr' package(s) announced via the SUSE-SU-2019:1962-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openexr fixes the following issues:

Security issue fixed:

- CVE-2017-9111: Fixed an invalid write of size 8 in the storeSSE function in ImfOptimizedPixelReading.h (bsc#1040109).
- CVE-2017-9113: Fixed an invalid write of size 1 in the bufferedReadPixels function in ImfInputFile.cpp (bsc#1040113).
- CVE-2017-9115: Fixed an invalid write of size 2 in the = operator function inhalf.h (bsc#1040115).
- CVE-2018-18444: Fixed Out-of-bounds write in makeMultiView.cpp (bsc#1113455).
- CVE-2017-9112: Fixed invalid read of size 1 in the getBits function in ImfHuf.cpp (bsc#1040112).");

  script_tag(name:"affected", value:"'openexr' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libIlmImf-Imf_2_1-21", rpm:"libIlmImf-Imf_2_1-21~2.1.0~6.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr", rpm:"openexr~2.1.0~6.10.1", rls:"SLES12.0SP4"))) {
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
