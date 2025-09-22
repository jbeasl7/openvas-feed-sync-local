# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140121");
  script_version("2022-04-05T13:00:52+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-05 13:00:52 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-01-19 10:34:29 +0100 (Thu, 19 Jan 2017)");
  script_name("Docker Compliance Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gb_gather_linux_host_infos.nasl", "gb_docker_ssh_login_detect.nasl");
  script_mandatory_keys("docker/info");

  script_tag(name:"summary", value:"Runs the Docker Compliance Check.

  These tests are inspired by the CIS Docker Benchmark.");

  script_xref(name:"URL", value:"https://www.cisecurity.org/benchmark/docker/");

  script_add_preference(name:"Perform check:", type:"checkbox", value:"no", id:1);
  script_add_preference(name:"Report passed tests:", type:"checkbox", value:"no", id:2);
  script_add_preference(name:"Report failed tests:", type:"checkbox", value:"yes", id:3);
  script_add_preference(name:"Report errors:", type:"checkbox", value:"no", id:4);
  script_add_preference(name:"Minimum docker version for test 1.1:", type:"entry", value:"1.12", id:5);
  script_add_preference(name:"Report skipped tests:", type:"checkbox", value:"no", id:6);

# nb: How to add new docker test preferences. (Is same text as below script_add_preference block):
#     Pref value: always "yes"
#     Pref name: the 'title' part of docker_policy_tests.inc docker_test array
#     Pref type: Always "checkbox"
#     Pref id: Stays the same when name is modified. For new prefs it is the id of current last pref plus one
#     Location: New preferences are put at the end of the list of script_add_preference calls
  script_add_preference(name:"1.1 Use Linux Kernel >= 3.10.", type:"checkbox", value:"yes", id:7);
  script_add_preference(name:"2.5 Disable legacy registry v1.", type:"checkbox", value:"yes", id:8);
  script_add_preference(name:"3.9 Sensitive host system directories should not be mounted in containers.", type:"checkbox", value:"yes", id:9);
  script_add_preference(name:'5.0 Do not use propagation mode "shared" for mounts.', type:"checkbox", value:"yes", id:10);
  script_add_preference(name:"1.2 Use a up to date Docker version.", type:"checkbox", value:"yes", id:11);
  script_add_preference(name:"2.6 Enable live restore.", type:"checkbox", value:"yes", id:12);
  script_add_preference(name:"5.1 Isolate the containers from the hosts UTS namespace.", type:"checkbox", value:"yes", id:13);
  script_add_preference(name:"1.3 Do not use lxc execution driver.", type:"checkbox", value:"yes", id:14);
  script_add_preference(name:"2.7 Do not use Userland Proxy", type:"checkbox", value:"yes", id:15);
  script_add_preference(name:"5.2 Do not disable default seccomp profile.", type:"checkbox", value:"yes", id:16);
  script_add_preference(name:"1.4 Restrict network traffic between containers.", type:"checkbox", value:"yes", id:17);
  script_add_preference(name:"2.8 docker.service file ownership must set to root:root", type:"checkbox", value:"yes", id:18);
  script_add_preference(name:"5.3 Confirm cgroup usage.", type:"checkbox", value:"yes", id:19);
  script_add_preference(name:'1.5 Set the logging level to "info".', type:"checkbox", value:"yes", id:20);
  script_add_preference(name:"2.9 docker.service file permissions must set to 644 or more restrictive.", type:"checkbox", value:"yes", id:21);
  script_add_preference(name:"4.0 Do not run sshd within containers", type:"checkbox", value:"yes", id:22);
  script_add_preference(name:"5.4 Set no-new-privileges for Container.", type:"checkbox", value:"yes", id:23);
  script_add_preference(name:"1.6 Allow Docker to make changes to iptables.", type:"checkbox", value:"yes", id:24);
  script_add_preference(name:"4.1 Container ports mapped to a privileged port.", type:"checkbox", value:"yes", id:25);
  script_add_preference(name:"5.5 Do not share the hosts user namespaces.", type:"checkbox", value:"yes", id:26);
  script_add_preference(name:"1.7 Do not use insecure registries", type:"checkbox", value:"yes", id:27);
  script_add_preference(name:"4.2 Do not skip placing the container inside a separate network stack.", type:"checkbox", value:"yes", id:28);
  script_add_preference(name:"5.6 Docker socket must not mount inside any containers.", type:"checkbox", value:"yes", id:29);
  script_add_preference(name:'1.8 Do not use the "aufs" storage driver.', type:"checkbox", value:"yes", id:30);
  script_add_preference(name:"4.3 Use memory limit for container.", type:"checkbox", value:"yes", id:31);
  script_add_preference(name:"5.7 Avoid image sprawl.", type:"checkbox", value:"yes", id:32);
  script_add_preference(name:"1.9 Configure TLS authentication.", type:"checkbox", value:"yes", id:33);
  script_add_preference(name:"3.0 docker.socket file ownership must set to root:root", type:"checkbox", value:"yes", id:34);
  script_add_preference(name:"4.4 Use CPU priority for container.", type:"checkbox", value:"yes", id:35);
  script_add_preference(name:"5.8 Avoid container sprawl.", type:"checkbox", value:"yes", id:36);
  script_add_preference(name:"3.1 docker.socket file permissions must set to 644 or more restrictive.", type:"checkbox", value:"yes", id:37);
  script_add_preference(name:"4.5 Containers root filesystem should mounted as read only.", type:"checkbox", value:"yes", id:38);
  script_add_preference(name:"3.2 /etc/docker directory ownership must set to root:root.", type:"checkbox", value:"yes", id:39);
  script_add_preference(name:"4.6 Bind incoming container traffic to a specific host interface.", type:"checkbox", value:"yes", id:40);
  script_add_preference(name:"3.3 /etc/docker directory permissions must set to 755 or more restrictive", type:"checkbox", value:"yes", id:41);
  script_add_preference(name:'4.7 Set the "on-failure" container restart policy to 5 or less.', type:"checkbox", value:"yes", id:42);
  script_add_preference(name:"2.0 Enable a default ulimit as appropriate.", type:"checkbox", value:"yes", id:43);
  script_add_preference(name:"3.4 Docker socket file ownership must set to root:docker.", type:"checkbox", value:"yes", id:44);
  script_add_preference(name:"4.8 Isolate the containers from the hosts process namespace.", type:"checkbox", value:"yes", id:45);
  script_add_preference(name:"2.1 Enable user namespace support.", type:"checkbox", value:"yes", id:46);
  script_add_preference(name:"3.5 Docker socket file permissions must set to 660 or more restrictive.", type:"checkbox", value:"yes", id:47);
  script_add_preference(name:"4.9 Isolate the containers from the hosts IPC namespace.", type:"checkbox", value:"yes", id:48);
  script_add_preference(name:"2.2 Check default cgroup usage.", type:"checkbox", value:"yes", id:49);
  script_add_preference(name:"3.6 Do not use user root for container.", type:"checkbox", value:"yes", id:50);
  script_add_preference(name:"2.3 Do not increase base device size if not needed.", type:"checkbox", value:"yes", id:51);
  script_add_preference(name:"3.7 Use HEALTHCHECK for the container image.", type:"checkbox", value:"yes", id:52);
  script_add_preference(name:"1.0 Use a separate partition for containers.", type:"checkbox", value:"yes", id:53);
  script_add_preference(name:"2.4 Make use of authorization plugins.", type:"checkbox", value:"yes", id:54);
  script_add_preference(name:"3.8 Do not use privileged containers.", type:"checkbox", value:"yes", id:55);

# nb: How to add new docker test preferences. (Is same text as above script_add_preference block):
#     Pref value: always "yes"
#     Pref name: the 'title' part of docker_policy_tests.inc docker_test array
#     Pref type: Always "checkbox"
#     Pref id: Stays the same when name is modified. For new prefs it is the id of current last pref plus one
#     Location: New preferences are put at the end of the list of script_add_preference calls

  script_tag(name:"qod", value:"98");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("misc_func.inc");
include("docker.inc");
include("docker_policy_tests.inc");
include("docker_policy.inc");
include("list_array_func.inc");

docker_test_init();

if( docker_test_is_enabled( "1.0" ) ) docker_test_1_0();
if( docker_test_is_enabled( "1.1" ) ) docker_test_1_1();
if( docker_test_is_enabled( "1.2" ) ) docker_test_1_2();
if( docker_test_is_enabled( "1.3" ) ) docker_test_1_3();
if( docker_test_is_enabled( "1.4" ) ) docker_test_1_4();
if( docker_test_is_enabled( "1.5" ) ) docker_test_1_5();
if( docker_test_is_enabled( "1.6" ) ) docker_test_1_6();
if( docker_test_is_enabled( "1.7" ) ) docker_test_1_7();
if( docker_test_is_enabled( "1.8" ) ) docker_test_1_8();
if( docker_test_is_enabled( "1.9" ) ) docker_test_1_9();
if( docker_test_is_enabled( "2.0" ) ) docker_test_2_0();
if( docker_test_is_enabled( "2.1" ) ) docker_test_2_1();
if( docker_test_is_enabled( "2.2" ) ) docker_test_2_2();
if( docker_test_is_enabled( "2.3" ) ) docker_test_2_3();
if( docker_test_is_enabled( "2.4" ) ) docker_test_2_4();
if( docker_test_is_enabled( "2.5" ) ) docker_test_2_5();
if( docker_test_is_enabled( "2.6" ) ) docker_test_2_6();
if( docker_test_is_enabled( "2.7" ) ) docker_test_2_7();
if( docker_test_is_enabled( "2.8" ) ) docker_test_2_8();
if( docker_test_is_enabled( "2.9" ) ) docker_test_2_9();
if( docker_test_is_enabled( "3.0" ) ) docker_test_3_0();
if( docker_test_is_enabled( "3.1" ) ) docker_test_3_1();
if( docker_test_is_enabled( "3.2" ) ) docker_test_3_2();
if( docker_test_is_enabled( "3.3" ) ) docker_test_3_3();
if( docker_test_is_enabled( "3.4" ) ) docker_test_3_4();
if( docker_test_is_enabled( "3.5" ) ) docker_test_3_5();
if( docker_test_is_enabled( "3.6" ) ) docker_test_3_6();
if( docker_test_is_enabled( "3.7" ) ) docker_test_3_7();
if( docker_test_is_enabled( "3.8" ) ) docker_test_3_8();
if( docker_test_is_enabled( "3.9" ) ) docker_test_3_9();
if( docker_test_is_enabled( "4.0" ) ) docker_test_4_0();
if( docker_test_is_enabled( "4.1" ) ) docker_test_4_1();
if( docker_test_is_enabled( "4.2" ) ) docker_test_4_2();
if( docker_test_is_enabled( "4.3" ) ) docker_test_4_3();
if( docker_test_is_enabled( "4.4" ) ) docker_test_4_4();
if( docker_test_is_enabled( "4.5" ) ) docker_test_4_5();
if( docker_test_is_enabled( "4.6" ) ) docker_test_4_6();
if( docker_test_is_enabled( "4.7" ) ) docker_test_4_7();
if( docker_test_is_enabled( "4.8" ) ) docker_test_4_8();
if( docker_test_is_enabled( "4.9" ) ) docker_test_4_9();
if( docker_test_is_enabled( "5.0" ) ) docker_test_5_0();
if( docker_test_is_enabled( "5.1" ) ) docker_test_5_1();
if( docker_test_is_enabled( "5.2" ) ) docker_test_5_2();
if( docker_test_is_enabled( "5.3" ) ) docker_test_5_3();
if( docker_test_is_enabled( "5.4" ) ) docker_test_5_4();
if( docker_test_is_enabled( "5.5" ) ) docker_test_5_5();
if( docker_test_is_enabled( "5.6" ) ) docker_test_5_6();
if( docker_test_is_enabled( "5.7" ) ) docker_test_5_7();
if( docker_test_is_enabled( "5.8" ) ) docker_test_5_8();

docker_test_end();

exit( 0 );
