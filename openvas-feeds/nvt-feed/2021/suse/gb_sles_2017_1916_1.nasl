# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1916.1");
  script_cve_id("CVE-2016-9262", "CVE-2016-9388", "CVE-2016-9389", "CVE-2016-9390", "CVE-2016-9391", "CVE-2016-9392", "CVE-2016-9393", "CVE-2016-9394", "CVE-2017-1000050");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-20 15:03:33 +0000 (Thu, 20 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1916-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1916-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171916-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047958");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-July/003054.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jasper' package(s) announced via the SUSE-SU-2017:1916-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for jasper fixes the following issues:

Security issues fixed:
- CVE-2016-9262: Multiple integer overflows in the jas_realloc function in base/jas_malloc.c and
 mem_resize function in base/jas_stream.c allow remote attackers to cause a denial of service via
 a crafted image, which triggers use after free vulnerabilities. (bsc#1009994)
- CVE-2016-9388: The ras_getcmap function in ras_dec.c allows remote attackers to cause a denial
 of service (assertion failure) via a crafted image file. (bsc#1010975)
- CVE-2016-9389: The jpc_irct and jpc_iict functions in jpc_mct.c allow remote attackers to cause a
 denial of service (assertion failure). (bsc#1010968)
- CVE-2016-9390: The jas_seq2d_create function in jas_seq.c allows remote attackers to cause a
 denial of service (assertion failure) via a crafted image file. (bsc#1010774)
- CVE-2016-9391: The jpc_bitstream_getbits function in jpc_bs.c allows remote attackers to cause a
 denial of service (assertion failure) via a very large integer. (bsc#1010782)
- CVE-2017-1000050: The jp2_encode function in jp2_enc.c allows remote attackers to cause a denial
 of service. (bsc#1047958)

CVEs already fixed with previous update:
- CVE-2016-9392: The calcstepsizes function in jpc_dec.c allows remote attackers to cause a denial
 of service (assertion failure) via a crafted file. (bsc#1010757)
- CVE-2016-9393: The jpc_pi_nextrpcl function in jpc_t2cod.c allows remote attackers to cause a
 denial of service (assertion failure) via a crafted file. (bsc#1010766)
- CVE-2016-9394: The jas_seq2d_create function in jas_seq.c allows remote attackers to cause a
 denial of service (assertion failure) via a crafted file. (bsc#1010756)");

  script_tag(name:"affected", value:"'jasper' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libjasper1", rpm:"libjasper1~1.900.14~195.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper1-32bit", rpm:"libjasper1-32bit~1.900.14~195.3.1", rls:"SLES12.0SP2"))) {
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
