# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1603.1");
  script_cve_id("CVE-2017-2581", "CVE-2017-2586", "CVE-2017-2587");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-19 17:54:59 +0000 (Wed, 19 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1603-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1603-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171603-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024294");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-June/002953.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netpbm' package(s) announced via the SUSE-SU-2017:1603-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for netpbm fixes the following issues:

Security bugs:
* CVE-2017-2586: A NULL pointer dereference in stringToUint function could lead to a denial of service (abort) problem when processing malformed images. [bsc#1024292]
* CVE-2017-2581: A out-of-bounds write in writeRasterPbm() could be used by attackers to crash the decoder or potentially execute code. [bsc#1024287]
* CVE-2017-2587: A insufficient size check of memory allocation in createCanvas() function could be used for a denial of service attack (memory exhaustion) [bsc#1024294]");

  script_tag(name:"affected", value:"'netpbm' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm11", rpm:"libnetpbm11~10.66.3~7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetpbm11-32bit", rpm:"libnetpbm11-32bit~10.66.3~7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netpbm", rpm:"netpbm~10.66.3~7.1", rls:"SLES12.0SP2"))) {
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
