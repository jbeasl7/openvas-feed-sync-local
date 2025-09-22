# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833177");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-45153");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 18:57:30 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:34:30 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for saphanabootstrap (SUSE-SU-2023:0009-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0009-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EXY4ZSVESCOLR26LGH3HLILBU73PKIN5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'saphanabootstrap'
  package(s) announced via the SUSE-SU-2023:0009-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for saphanabootstrap-formula fixes the following issues:

  - Version bump 0.13.1

  * revert changes to spec file to re-enable SLES RPM builds

  * CVE-2022-45153: Fixed privilege escalation for arbitrary users in
         hana/ha_cluster.sls (bsc#1205990)

  - Version bump 0.13.0

  * pass sid to sudoers in a SLES12 compatible way

  * add location constraint to gcp_stonith

  - Version bump 0.12.1

  * moved templates dir into hana dir in repository to be gitfs compatible

  - Version bump 0.12.0

  * add SAPHanaSR takeover blocker

  - Version bump 0.11.0

  * use check_cmd instead of tmp sudoers file

  * make sudoers rules more secure

  * migrate sudoers to template file

  - Version bump 0.10.1

  * fix hook removal conditions

  * fix majority_maker code on case grain is empty

  - Version bump 0.10.0

  * allow to disable shared HANA basepath and rework add_hosts code
         (enables HANA scale-out on AWS)

  * do not edit global.ini directly (if not needed)

  - Version bump 0.9.1

  * fix majority_maker code on case grain is empty

  - Version bump 0.9.0

  * define vip_mechanism for every provider and reorder resources (same
         schema for all SAP related formulas)

  - Version bump 0.8.1

  * use multi-target Hook on HANA scale-out

  - Version bump 0.8.0

  * add HANA scale-out support

  * add idempotence to not affect a running HANA and cluster

  - Version bump 0.7.2

  * add native fencing for microsoft-azure

  - fixes a not working import of dbapi in
       SUSE/ha-sap-terraform-deployments#703

  - removes the installation and extraction of all hdbcli files in the
       /hana/shared/srHook directory

  - fixes execution order of srTakeover/srCostOptMemConfig hook

  - renames and updates hook srTakeover to srCostOptMemConfig

  - Changing exporter stickiness to =  0 and adjusting the colocation score
       from +inf to -inf and changing the colocation from Master to Slave. This
       change fix the impact of a failed exporter in regards to the HANA DB.

  - Document extra_parameters in pillar.example (bsc#1185643)

  - Change hanadb_exporter default timeout value to 30 seconds

  - Set correct stickiness for the azure-lb resource The azure-lb resource
       receives an stickiness=0 to not influence on transitions calculations as
       the HANA resources have more priority");

  script_tag(name:"affected", value:"'saphanabootstrap' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"saphanabootstrap-formula", rpm:"saphanabootstrap-formula~0.13.1+git.1667812208.4db963e~150200.3.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"saphanabootstrap-formula", rpm:"saphanabootstrap-formula~0.13.1+git.1667812208.4db963e~150200.3.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"saphanabootstrap-formula", rpm:"saphanabootstrap-formula~0.13.1+git.1667812208.4db963e~150200.3.15.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"saphanabootstrap-formula", rpm:"saphanabootstrap-formula~0.13.1+git.1667812208.4db963e~150200.3.15.1", rls:"openSUSELeap15.3"))) {
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