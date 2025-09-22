# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851855");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-08-16 05:51:36 +0200 (Thu, 16 Aug 2018)");
  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-5156", "CVE-2018-5188");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-06 18:39:00 +0000 (Thu, 06 Dec 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for seamonkey openSUSE-SU-2018:2330-1 (seamonkey)");
  script_tag(name:"summary", value:"Check the version of seamonkey");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for seamonkey fixes the following issues:

  Mozilla Seamonkey was updated to 2.49.4:

  Now uses Gecko 52.9.1esr (boo#1098998).

  Security issues fixed with MFSA 2018-16 (boo#1098998):

  * CVE-2018-12359: Buffer overflow using computed size of canvas element

  * CVE-2018-12360: Use-after-free when using focus()

  * CVE-2018-12362: Integer overflow in SSSE3 scaler

  * CVE-2018-5156: Media recorder segmentation fault when track type is
  changed during capture

  * CVE-2018-12363: Use-after-free when appending DOM nodes

  * CVE-2018-12364: CSRF attacks through 307 redirects and NPAPI plugins

  * CVE-2018-12365: Compromised IPC child process can list local filenames

  * CVE-2018-12366: Invalid data handling during QCMS transformations

  * CVE-2018-5188: Memory safety bugs fixed in Firefox 60, Firefox ESR 60.1,
  and Firefox ESR 52.9

  Localizations finally included again (boo#1062195)

  Updated summary and description to more accurately reflect what SeaMonkey
  is, giving less prominence to the long- discontinued Mozilla Application
  Suite that many users may no longer be familiar with

  Update to Seamonkey 2.49.2

  * Gecko 52.6esr (including security relevant fixes) (boo#1077291)

  * fix issue in Composer

  * With some themes, the menulist- and history-dropmarker didn't show

  * Scrollbars didn't show the buttons

  * WebRTC has been disabled by default. It needs an add-on to enable it per
  site

  * The active title bar was not visually emphasized

  Correct requires and provides handling (boo#1076907)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-867=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-867=1");
  script_tag(name:"affected", value:"seamonkey on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"openSUSE-SU", value:"2018:2330_1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-08/msg00051.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.49.4~13.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~2.49.4~13.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-debugsource", rpm:"seamonkey-debugsource~2.49.4~13.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-common", rpm:"seamonkey-translations-common~2.49.4~13.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-other", rpm:"seamonkey-translations-other~2.49.4~13.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}