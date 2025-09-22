# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.14424.1");
  script_cve_id("CVE-2020-14397", "CVE-2020-14398", "CVE-2020-14399", "CVE-2020-14400", "CVE-2020-14401", "CVE-2020-14402");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-28 14:07:53 +0000 (Tue, 28 Jul 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:14424-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:14424-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-202014424-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173880");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-July/007150.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'LibVNCServer' package(s) announced via the SUSE-SU-2020:14424-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for LibVNCServer fixes the following issues:

- security update
- added patches
 fix CVE-2020-14398 [bsc#1173880], improperly closed TCP connection causes an infinite loop in libvncclient/sockets.c
 + LibVNCServer-CVE-2020-14398.patch
 fix CVE-2020-14397 [bsc#1173700], NULL pointer dereference in libvncserver/rfbregion.c
 + LibVNCServer-CVE-2020-14397.patch
 fix CVE-2020-14399 [bsc#1173743], Byte-aligned data is accessed through uint32_t pointers in libvncclient/rfbproto.c.
 + LibVNCServer-CVE-2020-14399.patch
 fix CVE-2020-14400 [bsc#1173691], Byte-aligned data is accessed through uint16_t pointers in libvncserver/translate.c.
 + LibVNCServer-CVE-2020-14400.patch
 fix CVE-2020-14401 [bsc#1173694], potential integer overflows in libvncserver/scale.c
 + LibVNCServer-CVE-2020-14401.patch
 fix CVE-2020-14402 [bsc#1173701], out-of-bounds access via encodings.
 + LibVNCServer-CVE-2020-14402,14403,14404.patch");

  script_tag(name:"affected", value:"'LibVNCServer' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"LibVNCServer", rpm:"LibVNCServer~0.9.1~160.19.1", rls:"SLES11.0SP4"))) {
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
