# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.13982.1");
  script_cve_id("CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3858", "CVE-2019-3859", "CVE-2019-3860", "CVE-2019-3861", "CVE-2019-3862", "CVE-2019-3863");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:29 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-26 14:10:46 +0000 (Tue, 26 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:13982-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:13982-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201913982-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128492");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128493");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh2_org' package(s) announced via the SUSE-SU-2019:13982-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libssh2_org fixes the following issues:

Security issues fixed:

- CVE-2019-3861: Fixed Out-of-bounds reads with specially crafted SSH packets (bsc#1128490).
- CVE-2019-3862: Fixed Out-of-bounds memory comparison with specially crafted message channel request packet (bsc#1128492).
- CVE-2019-3860: Fixed Out-of-bounds reads with specially crafted SFTP packets (bsc#1128481).
- CVE-2019-3863: Fixed an Integer overflow in user authenicate keyboard interactive which could allow out-of-bounds writes
 with specially crafted keyboard responses (bsc#1128493).
- CVE-2019-3856: Fixed a potential Integer overflow in keyboard interactive handling which could allow out-of-bounds write
 with specially crafted payload (bsc#1128472).
- CVE-2019-3859: Fixed Out-of-bounds reads with specially crafted payloads due to unchecked use of _libssh2_packet_require
 and _libssh2_packet_requirev (bsc#1128480).
- CVE-2019-3855: Fixed a potential Integer overflow in transport read which could allow out-of-bounds write with specially
 crafted payload (bsc#1128471).
- CVE-2019-3858: Fixed a potential zero-byte allocation which could lead to an out-of-bounds read with a specially crafted
 SFTP packet (bsc#1128476).
- CVE-2019-3857: Fixed a potential Integer overflow which could lead to zero-byte allocation and out-of-bounds with specially
 crafted message channel request SSH packet (bsc#1128474).");

  script_tag(name:"affected", value:"'libssh2_org' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1", rpm:"libssh2-1~1.4.3~17.3.1", rls:"SLES11.0SP4"))) {
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
