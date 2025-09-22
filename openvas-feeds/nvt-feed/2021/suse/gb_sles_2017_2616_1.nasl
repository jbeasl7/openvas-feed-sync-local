# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2616.1");
  script_cve_id("CVE-2015-3294", "CVE-2015-8899", "CVE-2017-14491", "CVE-2017-14492", "CVE-2017-14493", "CVE-2017-14494", "CVE-2017-14495", "CVE-2017-14496");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-13 19:27:11 +0000 (Fri, 13 Oct 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2616-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2616-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172616-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060361");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972164");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-October/003268.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq' package(s) announced via the SUSE-SU-2017:2616-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dnsmasq fixes the following issues.

Remedy the following security issues:

- CVE-2017-14491: 2 byte heap based overflow. [bsc#1060354]
- CVE-2017-14492: heap based overflow. [bsc#1060355]
- CVE-2017-14493: stack based overflow. [bsc#1060360]
- CVE-2017-14494: DHCP - info leak. [bsc#1060361]
- CVE-2017-14495: DNS - OOM DoS. [bsc#1060362]
- CVE-2017-14496: DNS - DoS Integer underflow. [bsc#1060364]
- Prevent a man-in-the-middle attack (bsc#972164, fate#321175).

Furthermore, the following issues have been fixed:

- Fix DHCP relaying, broken in 2.76 and 2.77.
- Update to version 2.78 (fate#321175, fate#322030, bsc#1035227).
- Fix PXE booting for UEFI architectures (fate#322030).
- Drop PrivateDevices=yes which breaks logging (bsc#902511, bsc#904537)
- Build with support for DNSSEC (fate#318323, bsc#908137).

Please note that this update brings a (small) potential incompatibility in the handling of 'basename' in --pxe-service. Please read the CHANGELOG and the documentation if you are using this option.");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on SUSE Linux Enterprise Server 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq", rpm:"dnsmasq~2.78~6.6.1", rls:"SLES12.0"))) {
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
