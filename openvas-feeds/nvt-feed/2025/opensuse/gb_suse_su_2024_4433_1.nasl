# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856887");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:4433-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4433-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244433-1.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-December/020055.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'govulncheck-vulndb' package(s) announced via the SUSE-SU-2024:4433-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for govulncheck-vulndb fixes the following issues:

- Update to version 0.0.20241218T202206 2024-12-18T20:22:06Z. (jsc#PED-11136)
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2024-3333

- Update to version 0.0.20241218T163557 2024-12-18T16:35:57Z. (jsc#PED-11136)
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2024-3331 GHSA-9j3m-fr7q-jxfw
 * GO-2024-3334 GHSA-qqc8-rv37-79q5
 * GO-2024-3335 GHSA-xx83-cxmq-x89m
 * GO-2024-3336 GHSA-cwq8-g58r-32hg
 * GO-2024-3337 GHSA-69pr-78gv-7c6h
 * GO-2024-3338 GHSA-826h-p4c3-477p
 * GO-2024-3339 GHSA-8wcc-m6j2-qxvm
 * GO-2024-3340 GHSA-v647-h8jj-fw5r

- Update to version 0.0.20241213T205935 2024-12-13T20:59:35Z. (jsc#PED-11136)
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2022-0635 GHSA-7f33-f4f5-xwgw
 * GO-2022-0646 GHSA-f5pg-7wfw-84q9
 * GO-2022-0828 GHSA-fx8w-mjvm-hvpc
 * GO-2023-2170 GHSA-q78c-gwqw-jcmc
 * GO-2023-2330 GHSA-7fxm-f474-hf8w
 * GO-2024-2901 GHSA-8hqg-whrw-pv92
 * GO-2024-3104 GHSA-846m-99qv-67mg
 * GO-2024-3122 GHSA-q3hw-3gm4-w5cr
 * GO-2024-3140 GHSA-xxxw-3j6h-q7h6
 * GO-2024-3169 GHSA-fhqq-8f65-5xfc
 * GO-2024-3186 GHSA-586p-749j-fhwp
 * GO-2024-3205 GHSA-xhr3-wf7j-h255
 * GO-2024-3218 GHSA-mqr9-hjr8-2m9w
 * GO-2024-3245 GHSA-95j2-w8x7-hm88
 * GO-2024-3248 GHSA-p26r-gfgc-c47h
 * GO-2024-3259 GHSA-p7mv-53f2-4cwj
 * GO-2024-3265 GHSA-gppm-hq3p-h4rp
 * GO-2024-3268 GHSA-r864-28pw-8682
 * GO-2024-3279 GHSA-7225-m954-23v7
 * GO-2024-3282 GHSA-r4pg-vg54-wxx4
 * GO-2024-3286 GHSA-27wf-5967-98gx
 * GO-2024-3293
 * GO-2024-3295 GHSA-55v3-xh23-96gh
 * GO-2024-3302 GHSA-px8v-pp82-rcvr
 * GO-2024-3306 GHSA-7mwh-q3xm-qh6p
 * GO-2024-3312 GHSA-4c49-9fpc-hc3v
 * GO-2024-3313 GHSA-jpmc-7p9c-4rxf
 * GO-2024-3314 GHSA-c2xf-9v2r-r2rx
 * GO-2024-3315
 * GO-2024-3319 GHSA-vmg2-r3xv-r3xf
 * GO-2024-3321 GHSA-v778-237x-gjrc
 * GO-2024-3323 GHSA-25w9-wqfq-gwqx
 * GO-2024-3324 GHSA-4pjc-pwgq-q9jp
 * GO-2024-3325 GHSA-c7xh-gjv4-4jgv
 * GO-2024-3326 GHSA-fqj6-whhx-47p7
 * GO-2024-3327 GHSA-xx68-37v4-4596
 * GO-2024-3330 GHSA-7prj-hgx4-2xc3");

  script_tag(name:"affected", value:"'govulncheck-vulndb' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"govulncheck-vulndb", rpm:"govulncheck-vulndb~0.0.20241218T202206~150000.1.23.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"govulncheck-vulndb", rpm:"govulncheck-vulndb~0.0.20241218T202206~150000.1.23.1", rls:"openSUSELeap15.6"))) {
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
