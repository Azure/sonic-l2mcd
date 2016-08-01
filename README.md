SONiC NAS NDI API
=================

NDI API definitions for the SONiC project

Description
-----------

This repo contains the NDI API definitions of the Network abstraction service. It provides header files that define data structures and prototypes used by NAS modules to access NDI functions.

Building
---------
Please see the instructions in the sonic-nas-manifest repo for more details on the common build tools.  [Sonic-nas-manifest](https://stash.force10networks.com/projects/SONIC/repos/sonic-nas-manifest/browse)

Development Dependencies:
 - sonic-common
 - sonic-object-library
 - sonic-base-model

Dependent Packages:
  libsonic-logging-dev libsonic-logging1 libsonic-model1 libsonic-model-dev libsonic-common1 libsonic-common-dev libsonic-object-library1 libsonic-object-library-dev

BUILD CMD: sonic_build --dpkg libsonic-logging-dev libsonic-logging1 libsonic-model1 libsonic-model-dev libsonic-common1 libsonic-common-dev libsonic-object-library1 libsonic-object-library-dev -- clean binary

(c) Dell 2016
