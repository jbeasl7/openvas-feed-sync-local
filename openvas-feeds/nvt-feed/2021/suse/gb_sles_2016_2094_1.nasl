# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2094.1");
  script_cve_id("CVE-2015-1798", "CVE-2015-1799", "CVE-2015-5194", "CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7848", "CVE-2015-7849", "CVE-2015-7850", "CVE-2015-7851", "CVE-2015-7852", "CVE-2015-7853", "CVE-2015-7854", "CVE-2015-7855", "CVE-2015-7871", "CVE-2015-7973", "CVE-2015-7974", "CVE-2015-7975", "CVE-2015-7976", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8158", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1549", "CVE-2016-1550", "CVE-2016-1551", "CVE-2016-2516", "CVE-2016-2517", "CVE-2016-2518", "CVE-2016-2519", "CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-4957");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-15 14:19:55 +0000 (Tue, 15 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2094-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2094-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162094-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'yast2-ntp-client' package(s) announced via the SUSE-SU-2016:2094-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The YaST2 NTP Client was updated to handle the presence of both xntp and ntp packages.
If none are installed, 'ntp' will be installed.
Security Issues:
CVE-2016-4953 CVE-2016-4954 CVE-2016-4955 CVE-2016-4956 CVE-2016-4957 CVE-2016-1547 CVE-2016-1548 CVE-2016-1549 CVE-2016-1550 CVE-2016-1551 CVE-2016-2516 CVE-2016-2517 CVE-2016-2518 CVE-2016-2519 CVE-2015-8158 CVE-2015-8138 CVE-2015-7979 CVE-2015-7978 CVE-2015-7977 CVE-2015-7976 CVE-2015-7975 CVE-2015-7974 CVE-2015-7973 CVE-2015-5300 CVE-2015-5194 CVE-2015-7871 CVE-2015-7855 CVE-2015-7854 CVE-2015-7853 CVE-2015-7852 CVE-2015-7851 CVE-2015-7850 CVE-2015-7849 CVE-2015-7848 CVE-2015-7701 CVE-2015-7703 CVE-2015-7704 CVE-2015-7705 CVE-2015-7691 CVE-2015-7692 CVE-2015-7702 CVE-2015-1798 CVE-2015-1799");

  script_tag(name:"affected", value:"'yast2-ntp-client' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"yast2-ntp-client", rpm:"yast2-ntp-client~2.13.18~0.20.1", rls:"SLES10.0SP4"))) {
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
