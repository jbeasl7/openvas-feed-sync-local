# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1825.1");
  script_cve_id("CVE-2017-15232", "CVE-2018-1152", "CVE-2018-11813");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:43 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-23 13:25:47 +0000 (Mon, 23 Jul 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1825-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1825-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181825-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098155");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-June/004223.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jpeg' package(s) announced via the SUSE-SU-2018:1825-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for jpeg fixes the following issues:

* CVE-2017-15232: NULL pointer dereferences in jdpostct.c and jquant1.c could
 lead to denial of service (crash) when processing images [bsc#1062937]
* CVE-2018-11813: Fixed the end-of-file mishandling in read_pixel in rdtarga.c,
 which allowed remote attackers to cause a denial-of-service via crafted JPG
 files due to a large loop [bsc#1096209]
* CVE-2018-1152: Fixed a denial of service in start_input_bmp() rdbmp.c caused
 by a divide by zero when processing a crafted BMP image [bsc#1098155]");

  script_tag(name:"affected", value:"'jpeg' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"jpeg", rpm:"jpeg~6b~879.12.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-32bit", rpm:"libjpeg-32bit~6.2.0~879.12.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg", rpm:"libjpeg~6.2.0~879.12.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-x86", rpm:"libjpeg-x86~6.2.0~879.12.7.1", rls:"SLES11.0SP4"))) {
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
