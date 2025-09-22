# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0553.1");
  script_cve_id("CVE-2010-1797", "CVE-2010-2497", "CVE-2010-2498", "CVE-2010-2499", "CVE-2010-2500", "CVE-2010-2519", "CVE-2010-2520", "CVE-2010-2527", "CVE-2010-2541", "CVE-2010-2805", "CVE-2010-3053", "CVE-2010-3054", "CVE-2010-3311", "CVE-2010-3814", "CVE-2010-3855", "CVE-2011-2895", "CVE-2011-3256", "CVE-2011-3439", "CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1129", "CVE-2012-1130", "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1133", "CVE-2012-1134", "CVE-2012-1135", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1138", "CVE-2012-1139", "CVE-2012-1141", "CVE-2012-1142", "CVE-2012-1143");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0553-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0553-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120553-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype2' package(s) announced via the SUSE-SU-2012:0553-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Specially crafted font files could have caused buffer overflows in freetype, which could have been exploited for remote code execution.

Security Issue references:

 * CVE-2012-1141
>
 * CVE-2012-1132
>
 * CVE-2012-1138
>
 * CVE-2012-1139
>
 * CVE-2011-2895
>
 * CVE-2012-1130
>
 * CVE-2010-3311
>
 * CVE-2012-1134
>
 * CVE-2010-2805
>
 * CVE-2010-3814
>
 * CVE-2012-1127
>
 * CVE-2012-1126
>
 * CVE-2010-1797
>
 * CVE-2010-3855
>
 * CVE-2010-2497
>
 * CVE-2012-1142
>
 * CVE-2010-3053
>
 * CVE-2012-1133
>
 * CVE-2012-1137
>
 * CVE-2011-3439
>
 * CVE-2012-1136
>
 * CVE-2012-1143
>
 * CVE-2011-3256
>
 * CVE-2012-1129
>
 * CVE-2012-1131
>
 * CVE-2010-3054
>
 * CVE-2012-1135
>
 * CVE-2010-2498
>
 * CVE-2010-2499
>
 * CVE-2010-2500
>
 * CVE-2010-2519
>
 * CVE-2010-2520
>
 * CVE-2010-2527
>
 * CVE-2010-2541
>");

  script_tag(name:"affected", value:"'freetype2' package(s) on SUSE Linux Enterprise Server 10-SP2.");

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

if(release == "SLES10.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.1.10~18.22.21.25", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-32bit", rpm:"freetype2-32bit~2.1.10~18.22.21.25", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.1.10~18.22.21.25", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-devel-32bit", rpm:"freetype2-devel-32bit~2.1.10~18.22.21.25", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ft2demos", rpm:"ft2demos~2.1.10~19.18.21.7", rls:"SLES10.0SP2"))) {
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
