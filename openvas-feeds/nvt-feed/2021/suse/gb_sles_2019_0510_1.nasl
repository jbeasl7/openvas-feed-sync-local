# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0510.1");
  script_cve_id("CVE-2016-7837", "CVE-2016-9800", "CVE-2016-9801", "CVE-2016-9804", "CVE-2016-9918", "CVE-2017-1000250");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-16 12:11:08 +0000 (Fri, 16 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0510-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0510-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190510-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057342");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-February/005161.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez' package(s) announced via the SUSE-SU-2019:0510-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bluez fixes the following issues:

Security issues fixed:

- CVE-2016-7837: Fixed possible buffer overflow, make sure we don't write past the end of the array.(bsc#1026652)
- CVE-2016-9800: Fix hcidump memory leak in pin_code_reply_dump() (bsc#1013721).
- CVE-2016-9801: Fixed a buffer overflow in set_ext_ctrl function (bsc#1013732)
- CVE-2016-9804: Fix hcidump buffer overflow in commands_dump() (bsc#1013877).
- CVE-2016-9918: Fixed an out-of-bounds read in packet_hexdump() (bsc#1015173)
- CVE-2017-1000250: Fixed a information leak in SDP (part of the recently published BlueBorne vulnerabilities) (bsc#1057342)");

  script_tag(name:"affected", value:"'bluez' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"bluez", rpm:"bluez~5.13~3.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluetooth3", rpm:"libbluetooth3~5.13~3.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"bluez", rpm:"bluez~5.13~3.10.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluetooth3", rpm:"libbluetooth3~5.13~3.10.1", rls:"SLES12.0SP1"))) {
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
