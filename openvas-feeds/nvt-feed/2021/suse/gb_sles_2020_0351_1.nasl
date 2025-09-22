# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0351.1");
  script_cve_id("CVE-2019-18902", "CVE-2019-18903", "CVE-2020-7216", "CVE-2020-7217");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-04 14:21:37 +0000 (Wed, 04 Mar 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0351-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0351-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200351-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160906");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-February/006465.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wicked' package(s) announced via the SUSE-SU-2020:0351-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wicked fixes the following issues:

Security issues fixed:

- CVE-2019-18902: Fixed a use-after-free when receiving invalid DHCP6 client options (bsc#1160903).
- CVE-2019-18903: Fixed a use-after-free when receiving invalid DHCP6 IA_PD option (bsc#1160904).
- CVE-2020-7216: Fixed a potential denial of service via a memory leak when processing packets with missing message type option in DHCP4 (bsc#1160905).
- CVE-2020-7217: Fixed a memory leak in DHCP4 fsm when processing packets for other client ids (bsc#1160906).

Non-security issue fixed:

- dhcp4: Fixed an intermittent hang during network setup by cleaning up the defer timer pointer (bsc#1142214).");

  script_tag(name:"affected", value:"'wicked' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"wicked", rpm:"wicked~0.6.60~3.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wicked-service", rpm:"wicked-service~0.6.60~3.5.1", rls:"SLES12.0SP5"))) {
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
