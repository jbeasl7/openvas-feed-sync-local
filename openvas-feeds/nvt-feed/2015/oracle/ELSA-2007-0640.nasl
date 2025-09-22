# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122643");
  script_cve_id("CVE-2007-4136");
  script_tag(name:"creation_date", value:"2015-10-08 11:50:01 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2007-0640)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2007-0640");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2007-0640.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'conga' package(s) announced via the ELSA-2007-0640 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.10.0-6.el5.0.1]
- Replaced Redhat copyrighted and trademarked images in the conga-0.10.0 tarball.

[0.10.0-6]

- Fixed bz253783
- Fixed bz253914 (conga doesn't allow you to reuse nfs export and nfs client resources)
- Fixed bz254038 (Impossible to set many valid quorum disk configurations via conga)
- Fixed bz253994 (Cannot specify multicast address for a cluster)
- Resolves: bz253783, bz253914, bz254038, bz253994

[0.10.0-5]

- Fixed bz249291 (delete node task fails to do all items listed in the help document)
- Fixed bz253341 (failure to start cluster service which had been modified for correction)
- Related: bz253341
- Resolves: bz249291

[0.10.0-4]

- Fixed bz230451 (fence_xvm.key file is not automatically created. Should have a least a default)
- Fixed bz249097 (allow a space as a valid password char)
- Fixed bz250834 (ZeroDivisionError when attempting to click an empty lvm volume group)
- Fixed bz250443 (storage name warning utility produces a storm of warnings which can lock your browser)
- Resolves: bz249097, bz250443, bz250834
- Related: bz230451

[0.10.0-3]

- Fixed bz245947 (luci/Conga cluster configuration tool not initializing cluster node members)
- Fixed bz249641 (conga is unable to do storage operations if there is an lvm snapshot present)
- Fixed bz249342 (unknown ricci error when adding new node to cluster)
- Fixed bz249291 (delete node task fails to do all items listed in the help document)
- Fixed bz249091 (RFE: tell user they are about to kill all their nodes)
- Fixed bz249066 (AttributeError when attempting to configure a fence device)
- Fixed bz249086 (Unable to add a new fence device to cluster)
- Fixed bz249868 (Use of failover domain not correctly shown)
- Resolves bz245947, bz249641, bz249342, bz249291, bz249091,
- Resolves bz249066, bz249086, bz249868
- Related: bz249351

[0.10.0-2]

- Fixed bz245202 (Conga needs to support Internet Explorer 6.0 and later)
- Fixed bz248317 (luci sets incorrect permissions on /usr/lib64/luci and /var/lib/luci)
- Resolves: bz245202 bz248317

[0.10.0-1]
- Fixed bz238655 (conga does not set the 'nodename' attribute for manual fencing)
- Fixed bz221899 (Node log displayed in partially random order)
- Fixed bz225782 (Need more luci service information on startup - no info written to log about failed start cause)
- Fixed bz227743 (Intermittent/recurring problem - when cluster is deleted, sometimes a node is not affected)
- Fixed bz227682 (saslauthd[2274]: Deprecated pam_stack module called from service 'ricci')
- Fixed bz238726 (Conga provides no way to remove a dead node from a cluster)
- Fixed bz239389 (conga cluster: make 'enable shared storage' the default)
- Fixed bz239596
- Fixed bz240034 (rpm verify fails on luci)
- Fixed bz240361 (Conga storage UI front-end is too slow rendering storage)
- Fixed bz241415 (Installation using Conga shows 'error' in message during reboot cycle.)
- Fixed bz241418 (Conga tries ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'conga' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"conga", rpm:"conga~0.10.0~6.el5.0.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luci", rpm:"luci~0.10.0~6.el5.0.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ricci", rpm:"ricci~0.10.0~6.el5.0.1", rls:"OracleLinux5"))) {
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
