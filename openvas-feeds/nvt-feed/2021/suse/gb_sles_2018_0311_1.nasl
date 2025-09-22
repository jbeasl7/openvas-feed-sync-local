# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0311.1");
  script_cve_id("CVE-2017-14970", "CVE-2017-9214", "CVE-2017-9263", "CVE-2017-9265");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-08 00:50:36 +0000 (Thu, 08 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0311-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0311-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180311-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061310");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-January/003692.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvswitch' package(s) announced via the SUSE-SU-2018:0311-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openvswitch fixes the following issues:

* CVE-2017-9263: While parsing an OpenFlow role status message, there is a call to the abort() functio for undefined role status reasons in the function `ofp_print_role_status_message` in `lib/ofp-print.c` that may be leveraged toward a remote DoS attack by a malicious switch. (bsc#1041470)
* CVE-2017-9265: Buffer over-read while parsing the group mod OpenFlow message sent from the controller in `lib/ofp-util.c` in the function `ofputil_pull_ofp15_group_mod`.(bsc#1041447)
* CVE-2017-9214: While parsing an OFPT_QUEUE_GET_CONFIG_REPLY type OFP 1.0 message, there is a buffer over-read that is caused by an unsigned integer underflow in the function `ofputil_pull_queue_get_config_reply10` in `lib/ofp-util.c`. (bsc#1040543)
* CVE-2017-14970: In lib/ofp-util.c, there are multiple memory leaks while parsing malformed OpenFlow group mod messages.(bsc#1061310)");

  script_tag(name:"affected", value:"'openvswitch' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"openvswitch", rpm:"openvswitch~2.5.1~25.12.7", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-dpdk", rpm:"openvswitch-dpdk~2.5.1~25.12.8", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-dpdk-switch", rpm:"openvswitch-dpdk-switch~2.5.1~25.12.8", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openvswitch-switch", rpm:"openvswitch-switch~2.5.1~25.12.7", rls:"SLES12.0SP2"))) {
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
