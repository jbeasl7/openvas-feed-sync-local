# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2350.1");
  script_cve_id("CVE-2013-7459");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:53 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-23 18:15:30 +0000 (Thu, 23 Feb 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2350-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2350-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172350-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pycrypto' package(s) announced via the SUSE-SU-2017:2350-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-pycrypto fixes the following issues:
- CVE-2013-7459: Fixed a potential heap buffer overflow in ALGnew
 (bsc#1017420).
python-paramiko was adjusted to work together with this python-pycrypto change. (bsc#1047666)");

  script_tag(name:"affected", value:"'python-pycrypto' package(s) on SUSE Container as a Service Platform ALL, SUSE Enterprise Storage 3, SUSE Enterprise Storage 4, SUSE Linux Enterprise Module for Advanced Systems Management 12, SUSE Linux Enterprise Module for Public Cloud 12, SUSE Linux Enterprise Module for Web Scripting 12, SUSE Linux Enterprise Point of Sale 12-SP2, SUSE Manager Proxy 3.0, SUSE Manager Proxy 3.1, SUSE Manager Server 3.0, SUSE Manager Server 3.1, SUSE Manager Tools 12, SUSE OpenStack Cloud 6, SUSE OpenStack Cloud 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-paramiko", rpm:"python-paramiko~1.15.2~2.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pycrypto", rpm:"python-pycrypto~2.6.1~10.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pycrypto-debuginfo", rpm:"python-pycrypto-debuginfo~2.6.1~10.3.1", rls:"SLES12.0"))) {
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
