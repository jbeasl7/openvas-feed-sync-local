# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.13951.1");
  script_cve_id("CVE-2019-6446");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-22 15:52:32 +0000 (Tue, 22 Jan 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:13951-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:13951-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201913951-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122208");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-February/005104.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-numpy' package(s) announced via the SUSE-SU-2019:13951-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-numpy fixes the following issues:

Security issue fixed:

- CVE-2019-6446: Set allow_pickle to false by default to restrict loading untrusted content (bsc#1122208).
 With this update we decrease the possibility of allowing remote attackers to execute arbitrary code by
 misusing numpy.load(). A warning during runtime will show-up when the allow_pickle is not explicitly set.

NOTE: By applying this update the behavior of python-numpy changes, which might break your application.
In order to get the old behaviour back, you have to explicitly set `allow_pickle` to True. Be aware that this should only be done for trusted input, as loading untrusted input might lead to arbitrary code execution.");

  script_tag(name:"affected", value:"'python-numpy' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-numpy", rpm:"python-numpy~1.8.0~6.4.1", rls:"SLES11.0SP4"))) {
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
