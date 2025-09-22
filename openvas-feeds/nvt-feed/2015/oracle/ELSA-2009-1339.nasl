# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122450");
  script_cve_id("CVE-2008-6552");
  script_tag(name:"creation_date", value:"2015-10-08 11:45:35 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2009-1339)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1339");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1339.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rgmanager' package(s) announced via the ELSA-2009-1339 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.0.52-1.0.1]
- Update summary and description to be vendor neutral

[2.0.52-1]
- When vm.sh does a status check and gets 'no state' it is now treated as a
 running state.
- Resolves: rhb#514044

[2.0.51-1]
- In some cases virtual machines will be restarted after a successful migration
 when the cluster configuration is updated.
- Resolves: rhbz#505340

[2.0.50-1]
- Extra checks from the oracle agents have been removed.
- Several fixes to prevent DOS attacks through insecure use of /tmp/ files have
 been implemented.
- vm.sh now uses libvirt
- Users can now define an explicit service processing order when
 central_processing is enabled
- Resolves: rhbz#470917 rhbz#412911 rhbz#468691 rhbz#492828

[2.0.49-1]
- Rgmanger now checks to see if it has been killed by the OOM killer and if
 so, reboots the node.
- Resolves: rhbz#488072

[2.0.48-1]
- clulog now accepts '-' as the first character in messages.
- If expire_time is 0 max_restarts is no longer ignored.
- SAP scripts have been updated.
- Empty PID files no longer cause resource start failures.
- Recovery policy of type restart now works properly when using a resource
 based on ra-skelet.sh
- startup_wait option has been added to the mysql resource agent.
- samba.sh now kills the pid listed in the proper pid file.
- Handling of '-F' has been improved to fix issues with rgmanager crashing if
 no members of a restricted failover domain are online and rgmanager failing
 to correctly restart service is they fail on the first node.
- Enabled ability to prioritize services.
- It is now possible to cap the number of simultaneious status checks to
 prevent load spikes.
- Enabling a frozen service no longer fails and leaves the service in a failed
 state.
- Forking and cloning during status checks has been optimized to reduce load
 spikes.
- rg_test no longer hangs when running against a cluster due to the removal
 of an 8MB memory cap.
- Resolves: rhbz#471431 rhbz#475826 rhbz#474444 rhbz#449394 rhbz#481058 rhbz#483093 rhbz#486711 rhbz#486717 rhbz#482858 rhbz#487598 rhbz#488714 rhbz#250718 rhbz#490455");

  script_tag(name:"affected", value:"'rgmanager' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"rgmanager", rpm:"rgmanager~2.0.52~1.0.1.el5", rls:"OracleLinux5"))) {
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
