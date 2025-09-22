# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0393.1");
  script_cve_id("CVE-2016-9577", "CVE-2016-9578");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-24 18:40:52 +0000 (Mon, 24 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0393-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0393-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170393-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023079");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-February/002621.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spice' package(s) announced via the SUSE-SU-2017:0393-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This security update for spice fixes the following issues:

CVE-2016-9577: A buffer overflow in the spice server could have potentially been used
by unauthenticated attackers to execute arbitrary code. (bsc#1023078)
CVE-2016-9578: Unauthenticated attackers could have caused a denial of service via a crafted message. (bsc#1023079)");

  script_tag(name:"affected", value:"'spice' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"libspice-server1", rpm:"libspice-server1~0.12.4~8.12.1", rls:"SLES12.0"))) {
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
