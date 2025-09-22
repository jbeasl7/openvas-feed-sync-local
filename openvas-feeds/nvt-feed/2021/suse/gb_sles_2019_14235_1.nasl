# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.14235.1");
  script_cve_id("CVE-2019-15678", "CVE-2019-15679", "CVE-2019-15680", "CVE-2019-8287");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-01 18:21:31 +0000 (Fri, 01 Nov 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:14235-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:14235-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201914235-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155476");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-November/006203.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tightvnc' package(s) announced via the SUSE-SU-2019:14235-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tightvnc fixes the following issues:

- CVE-2019-15679: Fixed a heap buffer overflow in InitialiseRFBConnection
 which might lead to code execution (bsc#1155476).
- CVE-2019-8287: Fixed a global buffer overflow in HandleCoRREBBPmay which
 might lead to code execution (bsc#1155472).
- CVE-2019-15680: Fixed a null pointer dereference in HandleZlibBPP which
 could have led to denial of service (bsc#1155452).
- CVE-2019-15678: Fixed a heap buffer overflow in rfbServerCutText handler
 (bsc#1155442).");

  script_tag(name:"affected", value:"'tightvnc' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"tightvnc", rpm:"tightvnc~1.3.9~81.15.3.1", rls:"SLES11.0SP4"))) {
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
