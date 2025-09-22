# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2303.1");
  script_cve_id("CVE-2016-5116", "CVE-2016-6128", "CVE-2016-6132", "CVE-2016-6161", "CVE-2016-6207", "CVE-2016-6214", "CVE-2016-6905");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-09 15:48:45 +0000 (Tue, 09 Aug 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2303-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2303-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162303-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/995034");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-September/002271.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gd' package(s) announced via the SUSE-SU-2016:2303-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gd fixes the following issues:

 * CVE-2016-6214: Buffer over-read issue when parsing crafted TGA file [bsc#991436]
 * CVE-2016-6132: read out-of-bands was found in the parsing of TGA files using libgd [bsc#987577]
 * CVE-2016-6128: Invalid color index not properly handled [bsc#991710]
 * CVE-2016-6207: Integer overflow error within _gdContributionsAlloc() [bsc#991622]
 * CVE-2016-6161: global out of bounds read when encoding gif from malformed input withgd2togif [bsc#988032]
 * CVE-2016-5116: avoid stack overflow (read) with large names [bsc#982176]
 * CVE-2016-6905: Out-of-bounds read in function read_image_tga in gd_tga.c [bsc#995034]");

  script_tag(name:"affected", value:"'gd' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"gd", rpm:"gd~2.1.0~12.1", rls:"SLES12.0SP1"))) {
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
