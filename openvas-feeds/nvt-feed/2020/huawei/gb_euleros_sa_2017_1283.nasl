# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1283");
  script_cve_id("CVE-2017-15227", "CVE-2017-15228", "CVE-2017-15721", "CVE-2017-15722");
  script_tag(name:"creation_date", value:"2020-01-23 11:05:26 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:55+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:55 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-24 14:25:34 +0000 (Tue, 24 Oct 2017)");

  script_name("Huawei EulerOS: Security Advisory for irssi (EulerOS-SA-2017-1283)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1283");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2017-1283");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'irssi' package(s) announced via the EulerOS-SA-2017-1283 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Irssi before 1.0.5, when installing themes with unterminated colour formatting sequences, may access data beyond the end of the string.(CVE-2017-15228)

Irssi before 1.0.5, while waiting for the channel synchronisation, may incorrectly fail to remove destroyed channels from the query list, resulting in use-after-free conditions when updating the state later on.(CVE-2017-15227)

In Irssi before 1.0.5, certain incorrectly formatted DCC CTCP messages could cause a NULL pointer dereference. This is a separate, but similar, issue relative to CVE-2017-9468.(CVE-2017-15721)

In certain cases, Irssi before 1.0.5 may fail to verify that a Safe channel ID is long enough, causing reads beyond the end of the string.(CVE-2017-15722)");

  script_tag(name:"affected", value:"'irssi' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"irssi", rpm:"irssi~0.8.15~16.h2", rls:"EULEROS-2.0SP1"))) {
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
