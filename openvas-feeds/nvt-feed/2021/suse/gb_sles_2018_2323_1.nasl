# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2323.1");
  script_cve_id("CVE-2018-0360", "CVE-2018-0361", "CVE-2018-1000085", "CVE-2018-14679");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-03 13:14:58 +0000 (Wed, 03 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2323-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2323-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182323-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103040");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-August/004412.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2018:2323-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav to version 0.100.1 fixes the following issues:

The following security vulnerabilities were addressed:

- CVE-2018-0360: HWP integer overflow, infinite loop vulnerability (bsc#1101410)
- CVE-2018-0361: PDF object length check, unreasonably long time to parse relatively small file (bsc#1101412)
- CVE-2018-1000085: Fixed a out-of-bounds heap read in XAR parser (bsc#1082858)
- CVE-2018-14679: Libmspack heap buffer over-read in CHM parser (bsc#1103040)
- Buffer over-read in unRAR code due to missing max value checks in table initialization
- PDF parser bugs

The following other changes were made:

- Disable YARA support for licensing reasons (bsc#1101654).
- Add HTTPS support for clamsubmit
- Fix for DNS resolution for users on IPv4-only machines where IPv6 is not
 available or is link-local only");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.100.1~33.15.2", rls:"SLES12.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.100.1~33.15.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.100.1~33.15.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.100.1~33.15.2", rls:"SLES12.0SP3"))) {
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
