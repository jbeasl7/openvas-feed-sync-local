# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0254.1");
  script_cve_id("CVE-2017-11423", "CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12376", "CVE-2017-12377", "CVE-2017-12378", "CVE-2017-12379", "CVE-2017-12380", "CVE-2017-6418", "CVE-2017-6419", "CVE-2017-6420");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:48 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-08 17:31:27 +0000 (Thu, 08 Feb 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0254-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0254-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180254-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077732");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-January/003654.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2018:0254-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

- Update to security release 0.99.3 (bsc#1077732)
 * CVE-2017-12376 (ClamAV Buffer Overflow in handle_pdfname Vulnerability)
 * CVE-2017-12377 (ClamAV Mew Packet Heap Overflow Vulnerability)
 * CVE-2017-12379 (ClamAV Buffer Overflow in messageAddArgument Vulnerability)
 - these vulnerabilities could have allowed an unauthenticated,
 remote attacker to cause a denial of service (DoS) condition
 or potentially execute arbitrary code on an affected device.
 * CVE-2017-12374 (ClamAV use-after-free Vulnerabilities)
 * CVE-2017-12375 (ClamAV Buffer Overflow Vulnerability)
 * CVE-2017-12378 (ClamAV Buffer Over Read Vulnerability)
 * CVE-2017-12380 (ClamAV Null Dereference Vulnerability)
 - these vulnerabilities could have allowed an unauthenticated,
 remote attacker to cause a denial of service (DoS) condition on an affected device.
 * CVE-2017-6420 (bsc#1052448)
 - this vulnerability could have allowed remote attackers to cause a denial of service
 (use-after-free) via a crafted PE file with WWPack compression.
 * CVE-2017-6419 (bsc#1052449)
 - ClamAV could have allowed remote attackers to cause a denial of service
 (heap-based buffer overflow and application crash) or possibly
 have unspecified other impact via a crafted CHM file.
 * CVE-2017-11423 (bsc#1049423)
 - ClamAV could have allowed remote attackers to cause a denial of service
 (stack-based buffer over-read and application crash) via a crafted CAB file.
 * CVE-2017-6418 (bsc#1052466)
 - ClamAV could have allowed remote attackers to cause a denial
 of service (out-of-bounds read) via a crafted e-mail message.");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.99.3~0.20.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.99.3~0.20.3.2", rls:"SLES11.0SP4"))) {
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
